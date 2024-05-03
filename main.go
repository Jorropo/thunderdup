package main

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"sync"
	"sync/atomic"
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

var mlk sync.Mutex
var m = make(map[key][]string)
var totalUniqueFiles, totalDupFiles, totalUniqueBytes, totalDupBytes uint64

type kind uint8

const (
	_ kind = iota
	traversal
	scanning
)

type task struct {
	path string
	kind kind
}

var wg jsync.FWaitGroup
var queueLock sync.Mutex
var queueCond = sync.Cond{L: &queueLock}
var queue []task // FIXME: should be a resizable ring buffer
var currentlyWorkingWorkers uint

// decrementCurrentlyWorkingWorkers must be called while holding [queueLock].
func decrementCurrentlyWorkingWorkers() {
	currentlyWorkingWorkers--
	if currentlyWorkingWorkers == 0 && len(queue) == 0 {
		queueCond.Broadcast() // it's finished, tell everyone
	}
}

func grabNextWorkItem() (_ task, ok bool) {
	queueLock.Lock()
	defer queueLock.Unlock()
	for len(queue) == 0 {
		if currentlyWorkingWorkers == 0 {
			return task{}, false // no more work
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
		work, ok := grabNextWorkItem()
		if !ok {
			return
		}
		switch work.kind {
		case traversal:
			traverse(work.path)
		case scanning:
			scan(work.path)
		default:
			panic("unknown work kind sent")
		}
	}
}

func traverse(p string) {
	fs, err := os.ReadDir(p)
	if err != nil {
		print(p + ": (ReadDir): " + err.Error())
		queueLock.Lock()
		defer queueLock.Unlock()
		decrementCurrentlyWorkingWorkers()
		return
	}

	queueLock.Lock()
	defer queueLock.Unlock()
	for _, f := range fs {
		if t := f.Type(); t.IsRegular() {
			queue = append(queue, task{kind: scanning, path: filepath.Join(p, f.Name())})
		} else if t.IsDir() {
			queue = append(queue, task{kind: traversal, path: filepath.Join(p, f.Name())})
		}
	}

	decrementCurrentlyWorkingWorkers()
	if len(queue) != 0 {
		queueCond.Signal()
	}
}

func scan(p string) {
	defer func() {
		queueLock.Lock()
		defer queueLock.Unlock()
		decrementCurrentlyWorkingWorkers()
	}()

	f, err := os.Open(p)
	if err != nil {
		print(p + ": (Open): " + err.Error())
		return
	}
	defer f.Close()

	stat, err := f.Stat()
	if err != nil {
		print(p + ": (Stat): " + err.Error())
		return
	}
	length := uint64(stat.Size())
	if length < 4096 {
		return // don't bother with files too small
	}

	h := sha256.New()
	_, err = f.WriteTo(h)
	if err != nil {
		print(p + ": (WriteTo): " + err.Error())
		return
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
}

var totalDedupped atomic.Uint64

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
	queue = []task{{kind: traversal, path: "."}}

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

	print("total dedupped: " + humanize.IBytes(totalDedupped.Load()))
}
