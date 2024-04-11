package main

import (
	"crypto/sha256"
	"os"
	"path/filepath"
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

var wg sync.WaitGroup
var mlk sync.Mutex
var m = make(map[[sha256.Size]byte]string)
var backoff = make(chan struct{}, 1024*8)

func traverse(p string) {
	defer wg.Done()
	defer func() { <-backoff }()

	fs, err := os.ReadDir(p)
	if err != nil {
		print(p + ": (ReadDir): " + err.Error())
		wg.Done()
		return
	}

	for _, f := range fs {
		backoff <- struct{}{}
		if t := f.Type(); t.IsRegular() {
			wg.Add(1)
			go scan(filepath.Join(p, f.Name()))
		} else if t.IsDir() {
			wg.Add(1)
			go traverse(filepath.Join(p, f.Name()))
		}
	}
}

func scan(p string) {
	defer wg.Done()
	defer func() { <-backoff }()

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
	err = fsc.Control(func(sfd uintptr) {
		errr = tsc.Control(func(tfd uintptr) {
			errrr = unix.IoctlFileDedupeRange(int(sfd), &unix.FileDedupeRange{
				Src_length: length,
				Info:       []unix.FileDedupeRangeInfo{{Dest_fd: int64(tfd)}},
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
	wg.Add(1)
	backoff <- struct{}{}
	go traverse(".")
	wg.Wait()
}
