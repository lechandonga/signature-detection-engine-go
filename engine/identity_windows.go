//go:build windows

package engine

import "os"

func deviceOf(os.FileInfo) uint64    { return 0 }
func inodeOf(os.FileInfo) uint64     { return 0 }
func hasIdentityOf(os.FileInfo) bool { return false }
