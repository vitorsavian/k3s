//go:build !windows

package cert

import (
	"os"
	"syscall"
)

// fileOwner returns the uid and gid of the file.
func fileOwner(fi os.FileInfo) (uid, gid int, ok bool) {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return -1, -1, false
	}
	return int(st.Uid), int(st.Gid), true
}
