//go:build unix

package quarantine

import (
	"fmt"
	"os"
	"os/user"
	"strconv"
	"syscall"
)

// ownerOf devolve o dono do arquivo, para que o restore possa registrar quem
// era. Nao tentamos restaurar o dono: sem root nao da, e prometer o que nao se
// cumpre e pior que registrar a informacao e deixar clara a limitacao.
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
