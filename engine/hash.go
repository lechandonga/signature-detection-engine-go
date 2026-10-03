package engine

import (
	"crypto/sha256"
	"encoding/hex"
	"hash"
	"io"
	"os"
)

// hashRange hashes bytes [off, off+length) of f using an independent read
// cursor. It returns the hex digest and the number of bytes read.
func hashRange(f *os.File, off, length int64) (string, int64, error) {
	if length == 0 {
		sum := sha256.Sum256(nil)
		return hex.EncodeToString(sum[:]), 0, nil
	}
	if _, err := f.Seek(off, io.SeekStart); err != nil {
		return "", 0, err
	}
	h := sha256.New()
	n, err := io.CopyN(h, f, length)
	if err != nil {
		return "", n, err
	}
	return hex.EncodeToString(h.Sum(nil)), n, nil
}

// hashFileAll hashes the whole current file contents independently. It opens
// its own descriptor so it never interferes with the streaming read cursor.
func hashFileAll(path string) (string, int64, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", 0, err
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(h, f)
	if err != nil {
		return "", n, err
	}
	return hex.EncodeToString(h.Sum(nil)), n, nil
}

func restoreHash(state []byte) hash.Hash {
	h := sha256.New()
	mh, ok := h.(interface{ UnmarshalBinary([]byte) error })
	if !ok {
		return nil
	}
	if err := mh.UnmarshalBinary(state); err != nil {
		return nil
	}
	return h
}
