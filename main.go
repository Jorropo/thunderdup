/*
   This program is free software: you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation, either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <https://www.gnu.org/licenses/>.

   thunderdup Copyright (C) 2024 Jorropo
*/

package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"runtime/pprof"
	"slices"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/Jorropo/jsync"
	"github.com/dustin/go-humanize"
	"github.com/zeebo/xxh3"
	"golang.org/x/sys/unix"
)

const pageSize = 4096 // FIXME: should vary this properly, it's fine to underestimate but not overestimate
const maxInfos = (pageSize - unix.SizeofRawFileDedupeRange) / unix.SizeofRawFileDedupeRangeInfo

var printLock sync.Mutex
var printBuffer bytes.Buffer

func print(s string) {
	printW(func(w *bytes.Buffer) {
		printBuffer.WriteString(s)
		printBuffer.WriteByte('\n')
	})
}

func printW(f func(w *bytes.Buffer)) {
	printLock.Lock()
	defer printLock.Unlock()
	f(&printBuffer)
	printBuffer.WriteTo(os.Stderr)
}

type key struct {
	hash   uint64
	length uint64 // to be recovered by [dedup], the hash would cover this otherwise.
}

var targetMntId atomic.Uint64

var mlk sync.Mutex
var hashes = make(map[key][]string)
var totalUniqueFiles, totalDupFiles, totalUniqueBytes, totalDupBytes uint64

var llk sync.Mutex
var lengthes = make(map[uint64]string) // lengthes is used to lazily compute hashes, first bucket on size and only hash if multiple files with the same size are found

var wg jsync.FWaitGroup
var queueLock sync.Mutex
var queueCond = sync.Cond{L: &queueLock}
var queue []string // FIXME: should be a resizable ring buffer
var currentlyWorkingWorkers uint

var lazyHasherBackoff chan struct{}

var totalDedupped atomic.Uint64
var totalDeddupingErrors atomic.Uint64

// decrementCurrentlyWorkingWorkers must be called while holding [queueLock].
func decrementCurrentlyWorkingWorkers() {
	currentlyWorkingWorkers--
	if currentlyWorkingWorkers == 0 && len(queue) == 0 {
		queueCond.Broadcast() // it's finished, tell everyone
	}
}

func grabNextWorkItem() (_ string, ok bool) {
	queueLock.Lock()
	defer queueLock.Unlock()
	for len(queue) == 0 {
		if currentlyWorkingWorkers == 0 {
			return "", false // no more work
		}
		queueCond.Wait()
	}
	t := queue[0]
	queue[0] = "" // early gc
	queue = queue[1:]
	if len(queue) != 0 {
		queueCond.Signal() // there is more work
	}
	currentlyWorkingWorkers++
	return t, true
}

func worker() {
	defer wg.Done()

	for {
		p, ok := grabNextWorkItem()
		if !ok {
			return
		}
		if err := work(p); err != nil {
			print(p + ": " + err.Error())
		}

	}
}

func work(p string) error {
	needsDecrement := true
	defer func() {
		if !needsDecrement {
			return
		}
		queueLock.Lock()
		defer queueLock.Unlock()
		decrementCurrentlyWorkingWorkers()
	}()

	f, err := os.OpenFile(p, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		if errors.Is(err, syscall.ELOOP) {
			return nil // this is O_NOFOLLOW result, we tried to open a symlink, ignore
		}
		return fmt.Errorf("Open: %w", err)
	}
	defer f.Close()

	isFile, isDir, mntId, fileSize, blocksize, err := statx(f)
	if err != nil {
		return fmt.Errorf("statx: %w", err)
	}
	tgt := targetMntId.Load()
	if tgt == 0 {
		if targetMntId.CompareAndSwap(0, mntId) {
			// first statx, initialize
		} else if mntId != targetMntId.Load() {
			return nil
		}
	} else if mntId != tgt {
		return nil
	}

	if isDir {
		needsDecrement, err = traverse(f, p)
		return err
	}
	if isFile {
		return scan(f, p, fileSize, blocksize)
	}
	return nil
}

func traverse(f *os.File, p string) (needsDecrement bool, err error) {
	fs, err := f.ReadDir(0)
	if err != nil {
		return true, fmt.Errorf("ReadDir: %w", err)
	}

	queueLock.Lock()
	defer queueLock.Unlock()
	queue = slices.Grow(queue, len(fs))
	for _, f := range fs {
		queue = append(queue, filepath.Join(p, f.Name()))
	}

	decrementCurrentlyWorkingWorkers()
	if len(queue) != 0 {
		queueCond.Signal()
	}
	return false, nil
}

func statx(f *os.File) (isFile, isDir bool, mntId, fileSize, blocksize uint64, rerr error) {
	fsc, err := f.SyscallConn()
	if err != nil {
		rerr = fmt.Errorf("SyscallConn: %w", err)
		return
	}

	var stat unix.Statx_t
	var errr error
	err = fsc.Control(func(fd uintptr) {
		errr = unix.Statx(int(fd), "", unix.AT_EMPTY_PATH|unix.AT_SYMLINK_NOFOLLOW, unix.STATX_MNT_ID|unix.STATX_TYPE|unix.STATX_SIZE, &stat)
	})
	if err != nil {
		rerr = fmt.Errorf("Control: %w", err)
		return
	}
	if errr != nil {
		rerr = fmt.Errorf("Statx: %w", errr)
		return
	}
	isFile = stat.Mode&unix.S_IFMT == unix.S_IFREG
	isDir = stat.Mode&unix.S_IFMT == unix.S_IFDIR
	mntId = stat.Mnt_id
	fileSize = stat.Size
	blocksize = uint64(stat.Blksize)
	return
}

func scan(f *os.File, p string, length, blocksize uint64) error {
	if length < blocksize {
		return nil // don't bother with files too small
	}

	llk.Lock()
	other, alreadyExists := lengthes[length]
	if !alreadyExists {
		lengthes[length] = p // record ourself to be lazily started later
		llk.Unlock()

		mlk.Lock()
		defer mlk.Unlock()
		// Carefull here ! We are reporting stats before we hashed it, we will need to tweak stats later.
		totalUniqueBytes += length
		totalUniqueFiles++
		return nil
	}
	if other != "" {
		lengthes[length] = "" // indicate the other file isn't waiting to be started anymore
	}
	llk.Unlock()

	if other != "" {
		// other file was waiting for lazy hashing, hash it now
		lazyHasherBackoff <- struct{}{}
		wg.Add()
		go doLazyHash(other, length)
	}

	return hashFile(f, length, p, false)
}

func doLazyHash(other string, length uint64) {
	defer wg.Done()
	defer func() { <-lazyHasherBackoff }()

	if err := func() error {
		f, err := os.Open(other)
		if err != nil {
			return fmt.Errorf("Open: %w", err)
		}
		defer f.Close()

		return hashFile(f, length, other, true)
	}(); err != nil {
		print(other + ": " + err.Error())
	}
}

func hashFile(f *os.File, length uint64, p string, statsWereAlreadyRecorded bool) error {
	h := xxh3.New()
	_, err := f.WriteTo(h)
	if err != nil {
		return fmt.Errorf("WriteTo: %w", err)
	}
	sum := key{h.Sum64(), length}

	mlk.Lock()
	defer mlk.Unlock()
	l, ok := hashes[sum]
	if ok {
		if statsWereAlreadyRecorded {
			// we double counted, let's correct that
			totalUniqueBytes -= length
			totalUniqueFiles--
		}
		totalDupBytes += length
		totalDupFiles++
	} else {
		if statsWereAlreadyRecorded {
			// we already counted it as we were adding it to the lazy bucket
		} else {
			totalUniqueBytes += length
			totalUniqueFiles++
		}
	}
	hashes[sum] = append(l, p)
	return nil
}

func dedup(backoff chan struct{}, length uint64, paths ...string) {
	defer func() { <-backoff }()

	slices.Sort(paths) // FIXME: we need the first one for passing it to source, but do we need the other ones to be sorted ?

	var release, filesAreReady, filesHaveAllExited sync.WaitGroup

	filesHaveAllExited.Add(len(paths))
	defer filesHaveAllExited.Wait() // don't rely on scheduler fairness for bounding concurrency

	release.Add(1)
	defer release.Done()

	filesAreReady.Add(len(paths))

	var hasFailed atomic.Bool

	dedups := make([]unix.FileDedupeRangeInfo, len(paths))
	// FIXME: we don't need that many paths open at once, we could be more economical about fds if we only openned the current batch files.
	for i, p := range paths {
		// Use a goroutine instead of recursion and block the callback in case we have an enormous amount of duplicates.
		go func() {
			var good bool
			defer func() {
				if !good {
					filesAreReady.Done()
					hasFailed.Store(true)
					totalDeddupingErrors.Add(1)
				}
				filesHaveAllExited.Done()
			}()

			f, err := os.Open(p)
			if err != nil {
				print(p + ": (Open for dedup): " + err.Error())
				return
			}
			defer f.Close()

			fsc, err := f.SyscallConn()
			if err != nil {
				print(p + ": (SyscallConn): " + err.Error())
				return
			}

			err = fsc.Control(func(fd uintptr) {
				dedups[i].Dest_fd = int64(fd)
				good = true
				filesAreReady.Done()
				release.Wait()
			})
			if err != nil {
				print(p + ": (Control): " + err.Error())
				return
			}
		}()
	}

	printW(func(w *bytes.Buffer) {
		w.WriteString("deduplicating: ")
		w.WriteString(paths[0])
		for _, p := range paths[1:] {
			w.WriteString("\n\t- ")
			w.WriteString(p)
		}
		w.WriteByte('\n')
	})

	filesAreReady.Wait()

	valid := dedups[:0]
	for _, d := range dedups {
		if d.Dest_fd == 0 {
			continue
		}
		valid = append(valid, d)
	}

	if len(valid) < 2 {
		return
	}

	var dedupped uint64
	source := valid[0].Dest_fd
	valid = valid[1:]
	for {
		currentBatch := valid[:min(len(valid), maxInfos)]
		var offset uint64
		for {
			arg := &unix.FileDedupeRange{
				Src_length: length - offset,
				Src_offset: offset,
				Info:       currentBatch,
			}
			err := unix.IoctlFileDedupeRange(int(source), arg)
			if err != nil {
				print(paths[0] + ": (FileDedupeRange): " + err.Error())
				totalDeddupingErrors.Add(uint64(len(currentBatch)))
				return
			}

			var best uint64
			nextBatch := currentBatch[:0]
			for i, v := range currentBatch {
				bytesDedupped := v.Bytes_deduped
				dedupped += bytesDedupped
				if bytesDedupped < best {
					// this file is having issues, forget about it.
					continue
				}
				if best < bytesDedupped {
					// previous files were doing poorly, forget about them.
					best = bytesDedupped
					nextBatch = currentBatch[i:i]
				}
				v.Dest_offset += bytesDedupped
				nextBatch = append(nextBatch, v)
			}
			currentBatch = nextBatch
			offset += best

			if offset == length || best == 0 {
				break
			}
		}

		if len(valid) <= maxInfos {
			break
		}
		valid = valid[maxInfos:]
	}
	totalDedupped.Add(dedupped)
}

func main() {
	concurrencyFactor := flag.Int("cf", 4, "define the concurrency factor, this allows to set the amount of workers run per linux core, use GOMAXPROCS env to configure the number of cores used.")
	cpuprofile := flag.String("cpuprofile", "", "write cpu profile to `file`")
	onlyScan := flag.Bool("only-scan", false, "only scan and do not dedup")
	flag.Parse()
	if *concurrencyFactor <= 0 {
		print("concurrencyFactor must be > 0")
		return
	}
	if *cpuprofile != "" {
		f, err := os.Create(*cpuprofile)
		if err != nil {
			print("could not create CPU profile: " + err.Error())
		}
		defer f.Close()
		if err := pprof.StartCPUProfile(f); err != nil {
			print("could not start CPU profile: " + err.Error())
		}
		defer pprof.StopCPUProfile()
	}

	// Run in two stages to prevent undeduplicating deduplicated content, first scan everything.
	queue = flag.Args()
	if len(queue) == 0 {
		queue = []string{"."}
	} else {
		queue = queue[:len(queue):len(queue)] // make sure it is cloned on the first modification
	}

	concurrency := runtime.GOMAXPROCS(0) * *concurrencyFactor
	lazyHasherBackoff = make(chan struct{}, concurrency)
	done := make(chan struct{})
	wg.Init(func() { close(done) }, uint64(concurrency))
	for range concurrency {
		go worker()
	}

	print("Scanning ...")
	timer := time.NewTicker(time.Second)
	var exit bool
	for !exit {
		select {
		case <-done:
			exit = true
		case <-timer.C:
		}

		mlk.Lock()
		uniqueFiles := totalUniqueFiles
		uniqueBytes := totalUniqueBytes
		dupFiles := totalDupFiles
		dupBytes := totalDupBytes
		mlk.Unlock()

		queueLock.Lock()
		queueLength := len(queue)
		workingWorkers := currentlyWorkingWorkers
		queueLock.Unlock()

		lazyHashers := len(lazyHasherBackoff)
		var lazyHashersBonus string
		if lazyHashers != 0 {
			lazyHashersBonus = "+" + strconv.Itoa(lazyHashers)
		}

		printW(func(w *bytes.Buffer) {
			fmt.Fprintf(w, `%v:
	unique:    %d	%s
	duplicate: %d	%s
	queue length: %d
	currently working workers: %d%s/%d
`, time.Now().Format(time.DateTime), uniqueFiles, humanize.IBytes(uniqueBytes), dupFiles, humanize.IBytes(dupBytes), queueLength, workingWorkers, lazyHashersBonus, concurrency)
		})
	}
	timer.Stop()

	if *onlyScan {
		return
	}

	if totalDupFiles == 0 {
		print("No duplicate found !")
		return
	}
	print("Deduplicating ...")

	backoff := make(chan struct{}, concurrency)

	// Then dedup duplicates, pass all files in bulk to FileDedupeRange.
	for k, files := range hashes {
		hashes[k] = nil // early gc
		if len(files) < 2 {
			continue
		}
		backoff <- struct{}{}
		go dedup(backoff, k.length, files...)
	}

	for range concurrency {
		backoff <- struct{}{}
	}

	print("total dedupped: " + humanize.IBytes(totalDedupped.Load()) + "\ndedupping errors: " + strconv.FormatUint(totalDeddupingErrors.Load(), 10))
}
