package main

import (
	"crypto/sha256"
	"io"
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

func traverse(p string) {
	fs, err := os.ReadDir(p)
	if err != nil {
		print(p + ": (ReadDir): " + err.Error())
		wg.Done()
		return
	}

	var count int
	for _, f := range fs {
		if t := f.Type(); t.IsRegular() {
			count++
			go scan(filepath.Join(p, f.Name()))
		} else if t.IsDir() {
			count++
			go traverse(filepath.Join(p, f.Name()))
		}
	}
	if count == 0 {
		wg.Done()
		return
	}
	count-- // passthrough our own waitgroup count
	wg.Add(count)
}

func scan(p string) {
	defer wg.Done()

	f, err := os.Open(p)
	if err != nil {
		print(p + ": (Open): " + err.Error())
		return
	}
	defer f.Close()

	h := sha256.New()

	var buf [4096 * 8]byte
	var totlength uint64
loop:
	for {
		n, err := f.Read(buf[:])
		switch err {
		case nil:
		case io.EOF:
			break loop
		default:
			print(p + ": (Read): " + err.Error())
			return
		}

		totlength += uint64(n)
		h.Write(buf[:n])
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
				Src_length: totlength,
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
	go traverse(".")
	wg.Wait()
}
