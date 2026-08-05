//go:build unix

package quarantine

import (
	"fmt"
	"os"
	"syscall"
)

// otherNamesFor reports how many additional directory entries point at this file's
// content, and an error if the path is not what it appeared to be.
//
// `os.Remove` unlinks a NAME. It does not delete content, and it does not follow a
// symlink. Both of those turn "quarantined" into a sentence that is not true:
//
//   - A hard link needs no race at all. An attacker who uploads a payload and links it to
//     a second name has one flagged path and one that is not. Quarantining the flagged one
//     copies the content to the vault, unlinks that name, and reports success — while the
//     content stays exactly where it was, fully executable, under the other name.
//
//   - A symlink whose target holds identical bytes survives the hash re-check, because the
//     hash is of the target. The copy is made from the target, the removal takes the link,
//     and the payload is untouched.
//
// Neither is exotic. They are two commands, and the reward is a scanner that reports the
// threat handled — which is worse for the user than no scanner, because it ends the
// investigation.
func otherNamesFor(path string) (int, error) {
	// Lstat, never Stat: Stat follows the link and would describe the target, which is the
	// thing this is trying to notice.
	li, err := os.Lstat(path)
	if err != nil {
		return 0, fmt.Errorf("reading %s before acting: %w", path, err)
	}
	if li.Mode()&os.ModeSymlink != 0 {
		return 0, fmt.Errorf("%w: %s is a symbolic link. Removing it would delete the link "+
			"and leave the file it points at untouched, so this would report a quarantine "+
			"that did not happen. The scan skips symbolic links, so this one appeared "+
			"between the scan and now", ErrNotAPlainFile, path)
	}
	if !li.Mode().IsRegular() {
		return 0, fmt.Errorf("%w: %s is not a regular file", ErrNotAPlainFile, path)
	}

	st, ok := li.Sys().(*syscall.Stat_t)
	if !ok {
		// Unknown platform shape. Report zero rather than guessing: a wrong "there are
		// other names" would block a legitimate quarantine, and a wrong "there are none"
		// is the failure this exists to prevent — so the caller treats the error, not the
		// number, as the signal.
		return 0, fmt.Errorf("could not read the link count of %s on this platform", path)
	}
	if st.Nlink <= 1 {
		return 0, nil
	}
	// Nlink is unsigned and platform-sized. Clamping rather than converting: the caller
	// only branches on "more than zero", and a wrap on a 32-bit build could turn a file
	// with other names into one that looks safe to unlink — the exact failure this
	// function exists to prevent, produced by the arithmetic meant to detect it.
	const reportCap = 1 << 20
	others := st.Nlink - 1 // native unsigned type; Nlink > 1 was established above
	if others > reportCap {
		return reportCap, nil
	}
	return int(others), nil
}
