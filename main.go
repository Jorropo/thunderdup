package main

import (
	"crypto/sha256"
	"os"
	"path/filepath"
	"runtime"
	"sync"

	"golang.org/x/sys/unix"
)

var lk sync.Mutex

func print(s string) {
	lk.Lock()
	defer lk.Unlock()
	os.Stderr.WriteString(s)
	os.Stderr.WriteString("\n")
}

var mlk sync.Mutex
var m = make(map[[sha256.Size]byte]string)

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

var wg sync.WaitGroup
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
	sum := [sha256.Size]byte(h.Sum(nil))

	mlk.Lock()
	target, ok := m[sum]
	if !ok {
		m[sum] = p
		mlk.Unlock()
		return
	}
	mlk.Unlock()
	print("found dup: " + target + " " + p)

	tgt, err := os.Open(target)
	if err != nil {
		print(p + ": (target Open): " + err.Error())
		return
	}
	defer tgt.Close()

	fsc, err := f.SyscallConn()
	if err != nil {
		print(p + ": (SyscallConn): " + err.Error())
		return
	}

	tsc, err := tgt.SyscallConn()
	if err != nil {
		print(p + ": (target SyscallConn): " + err.Error())
		return
	}

	var errr, errrr error
	err = fsc.Control(func(ffd uintptr) {
		errr = tsc.Control(func(tfd uintptr) {
			errrr = unix.IoctlFileDedupeRange(int(tfd), &unix.FileDedupeRange{
				Src_length: length,
				Info:       []unix.FileDedupeRangeInfo{{Dest_fd: int64(ffd)}},
			})
		})
	})
	if err != nil {
		print(p + ": (Control): " + err.Error())
		return
	}
	if errr != nil {
		print(p + ": (target Control): " + errr.Error())
		return
	}
	if errrr != nil {
		print(p + ": (IoctlFileDedupeRange): " + errrr.Error())
		return
	}
}

func main() {
	queue = []task{{kind: traversal, path: "."}}

	concurrency := runtime.GOMAXPROCS(0) * 16
	wg.Add(concurrency)
	for range concurrency {
		go worker()
	}
	wg.Wait()
}
