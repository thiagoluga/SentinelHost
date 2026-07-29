//go:build unix

package quarantine

import (
	"fmt"
	"os"
	"os/user"
	"strconv"
	"syscall"
)

// ownerOf returns the file's owner, so the restore can record who it was. We do
// not try to restore the owner: without root it is impossible, and promising what
// cannot be delivered is worse than recording the information and stating the
// limitation plainly.
func ownerOf(info os.FileInfo) string {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || st == nil {
		return ""
	}
	uid := strconv.FormatUint(uint64(st.Uid), 10)
	if u, err := user.LookupId(uid); err == nil {
		return u.Username
	}
	return fmt.Sprintf("uid:%s", uid)
}
