//go:build !windows

package email

import "os"

// isExecutableFile reports whether the path is a regular file with an execute bit.
//
// The mode is checked rather than trusting the path to exist: a directory named
// /usr/sbin/sendmail, or a file with the bit cleared, would otherwise be handed to exec
// and fail at the point where the user is told their mail configuration is wrong.
func isExecutableFile(path string) bool {
	fi, err := os.Stat(path)
	if err != nil || fi.IsDir() {
		return false
	}
	return fi.Mode().Perm()&0o111 != 0
}
