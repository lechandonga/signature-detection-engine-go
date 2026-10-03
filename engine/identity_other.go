//go:build !linux && !darwin && !freebsd && !netbsd && !openbsd && !dragonfly

package engine

import "os"

// identify fingerprints a file without reading its content (portable form).
func identify(path string) (fileIdentity, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return fileIdentity{}, err
	}
	return fileIdentity{
		Size:    fi.Size(),
		MtimeNS: fi.ModTime().UnixNano(),
	}, nil
}
