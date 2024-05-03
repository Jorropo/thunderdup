package main

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/Jorropo/jsync"
	"github.com/dustin/go-humanize"
	"golang.org/x/sys/unix"
)

var printLock sync.Mutex

func print(s string) {
	printLock.Lock()
	defer printLock.Unlock()
	os.Stderr.WriteString(s)
	os.Stderr.WriteString("\n")
}

type key struct {
	hash   [sha256.Size]byte
	length uint64 // to be recovered by [dedup], the hash would cover this otherwise.
}

var targetMntId uint64

var mlk sync.Mutex
var m = make(map[key][]string)
var totalUniqueFiles, totalDupFiles, totalUniqueBytes, totalDupBytes uint64

var wg jsync.FWaitGroup
var queueLock sync.Mutex
var queueCond = sync.Cond{L: &queueLock}
var queue []string // FIXME: should be a resizable ring buffer
var currentlyWorkingWorkers uint

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

	f, err := os.OpenFile(p, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		if errors.Is(err, syscall.ELOOP) {
			return nil // this is O_NOFOLLOW result, we tried to open a symlink, ignore
		}
		return fmt.Errorf("Open: %w", err)
	}
	defer f.Close()

	isFile, isDir, mntId, fileSize, err := statx(f)
	if err != nil {
		return fmt.Errorf("statx: %w", err)
	}
	if targetMntId == 0 {
		targetMntId = mntId // first statx, initialize
	} else if mntId != targetMntId {
		return nil
	}

	if isDir {
		needsDecrement, err = traverse(f, p)
		return err
	}
	if isFile {
		return scan(f, p, fileSize)
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

func statx(f *os.File) (isFile, isDir bool, mntId uint64, fileSize uint64, rerr error) {
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
	return
}

func scan(f *os.File, p string, length uint64) error {
	if length < 4096 {
		return nil // don't bother with files too small
	}

	h := sha256.New()
	_, err := f.WriteTo(h)
	if err != nil {
		return fmt.Errorf("WriteTo: %w", err)
	}
	sum := key{[sha256.Size]byte(h.Sum(nil)), length}

	mlk.Lock()
	defer mlk.Unlock()
	l, ok := m[sum]
	if ok {
		totalDupBytes += length
		totalDupFiles++
	} else {
		totalUniqueBytes += length
		totalUniqueFiles++
	}
	m[sum] = append(l, p)
	return nil
}

var totalDedupped atomic.Uint64
var totalDeddupingErrors atomic.Uint64

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

	printLock.Lock()
	os.Stderr.WriteString("found dups: ")
	os.Stderr.WriteString(paths[0])
	for _, p := range paths[1:] {
		os.Stderr.WriteString("\n\t- ")
		os.Stderr.WriteString(p)
	}
	os.Stderr.WriteString("\n")
	printLock.Unlock()

	filesAreReady.Wait()

	valid := dedups[:]
	for _, d := range dedups {
		if d.Dest_fd == 0 {
			continue
		}
		valid = append(valid, d)
	}

	if len(valid) < 2 {
		return
	}

	err := unix.IoctlFileDedupeRange(int(valid[0].Dest_fd), &unix.FileDedupeRange{
		Src_length: length,
		Info:       valid[1:],
	})
	if err != nil {
		print(paths[0] + ": (FileDedupeRange): " + err.Error())
		totalDeddupingErrors.Add(uint64(len(valid)))
		return
	}

	var dedupped uint64
	for _, v := range valid[1:] {
		dedupped += v.Bytes_deduped
	}
	totalDedupped.Add(dedupped)
}

func main() {
	// Run in two stages to prevent undeduplicating deduplicated content, first scan everything.
	queue = []string{"."}

	concurrency := runtime.GOMAXPROCS(0) * 16
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

		printLock.Lock()
		fmt.Fprintf(os.Stderr, `%v:
	unique:    %d	%s
	duplicate: %d	%s
	queue length: %d
	currently working workers: %d/%d
`, time.Now().Format(time.DateTime), uniqueFiles, humanize.IBytes(uniqueBytes), dupFiles, humanize.IBytes(dupBytes), queueLength, workingWorkers, concurrency)
		printLock.Unlock()
	}
	timer.Stop()

	if totalDupFiles == 0 {
		print("No duplicate found !")
		return
	}
	print("Deduplicating ...")

	backoff := make(chan struct{}, concurrency)

	// Then dedup duplicates, pass all files in bulk to FileDedupeRange.
	for k, files := range m {
		m[k] = nil
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
