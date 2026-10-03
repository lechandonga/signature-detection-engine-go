//go:build !windows

package engine

import (
	"os"
	"syscall"
)

func deviceOf(fi os.FileInfo) uint64 {
	if s, ok := fi.Sys().(*syscall.Stat_t); ok {
		return uint64(s.Dev)
	}
	return 0
}

func inodeOf(fi os.FileInfo) uint64 {
	if s, ok := fi.Sys().(*syscall.Stat_t); ok {
		return s.Ino
	}
	return 0
}

func hasIdentityOf(fi os.FileInfo) bool {
	_, ok := fi.Sys().(*syscall.Stat_t)
	return ok
}
