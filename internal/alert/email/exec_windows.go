//go:build windows

package email

// isExecutableFile always reports false on Windows.
//
// There is no sendmail convention here, and the permission bits Stat reports are
// synthesised — every file looks executable, so the Unix check would claim to have found
// an MTA at a path that cannot exist. Reporting false sends the auto transport to SMTP,
// which is the only thing that could have worked anyway.
func isExecutableFile(string) bool { return false }
