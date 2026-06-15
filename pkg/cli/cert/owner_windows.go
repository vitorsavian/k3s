package cert

import "os"

// fileOwner is not supported on Windows, where file ownership is not expressed as a uid and gid.
func fileOwner(fi os.FileInfo) (uid, gid int, ok bool) {
	return -1, -1, false
}
