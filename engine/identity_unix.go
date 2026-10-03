//go:build linux || darwin || freebsd || netbsd || openbsd || dragonfly

package engine

import (
	"os"
	"syscall"
)

// identify fingerprints a file without reading its content.
func identify(path string) (fileIdentity, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return fileIdentity{}, err
	}
	sys, ok := fi.Sys().(*syscall.Stat_t)
	var dev, ino uint64
	if ok {
		dev = uint64(sys.Dev)
		ino = sys.Ino
	}
	return fileIdentity{
		Size:    fi.Size(),
		Dev:     dev,
		Ino:     ino,
		MtimeNS: fi.ModTime().UnixNano(),
	}, nil
}
