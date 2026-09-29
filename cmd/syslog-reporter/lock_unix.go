//go:build unix

package main

import (
	"errors"
	"os"
	"syscall"
)

// lockDaily takes an exclusive, non-blocking flock on path. held is true
// when another process has it. The lock lives on the open descriptor, not
// the file, so a stale lock file on disk blocks nothing, and the kernel
// drops it however the process ends.
func lockDaily(path string) (unlock func(), held bool, err error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o644)
	if err != nil {
		return nil, false, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) {
			return nil, true, nil
		}
		return nil, false, err
	}
	return func() { f.Close() }, false, nil
}
