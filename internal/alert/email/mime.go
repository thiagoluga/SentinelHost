package email

import "mime"

// mimeEncode aplica a codificacao RFC 2047 (base64 UTF-8) ao assunto.
func mimeEncode(s string) string {
	return mime.BEncoding.Encode("UTF-8", s)
}
