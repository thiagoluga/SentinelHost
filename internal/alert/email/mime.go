package email

import "mime"

// mimeEncode applies the RFC 2047 encoding (base64 UTF-8) to the subject.
func mimeEncode(s string) string {
	return mime.BEncoding.Encode("UTF-8", s)
}
