package engine

import "os"

// fileIdentity distinguishes "same file, appended to" from "path now points
// at a different file" (e.g. rotated or atomically replaced). On platforms
// without device/inode information only the size-independent mode bits are
// used; the prefix hash check is then the second line of defense.
type fileIdentity struct {
	dev   uint64
	inode uint64
	mode  os.FileMode
	ok    bool
}

func fileIdentityOf(fi os.FileInfo) fileIdentity {
	return fileIdentity{
		dev:   deviceOf(fi),
		inode: inodeOf(fi),
		mode:  fi.Mode(),
		ok:    hasIdentityOf(fi),
	}
}
