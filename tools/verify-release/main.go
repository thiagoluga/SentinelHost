// Command verify-release checks a downloaded release against a public key.
//
// The same check `sentinelhost update` performs, available before installing anything by
// hand. Somebody who downloads a release from the web page has no other way to answer
// "is this the file the maintainer signed" — the SHA256SUMS beside it comes from the same
// place as the binary, so it proves the transfer was not corrupted and nothing more.
//
//	go run ./tools/verify-release <binary> <binary>.sig <base64 public key>
package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
)

func main() {
	if len(os.Args) != 4 {
		fmt.Fprintln(os.Stderr, "usage: verify-release <binary> <signature> <base64 public key>")
		os.Exit(2)
	}
	payload, err := os.ReadFile(os.Args[1])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	rawSig, err := os.ReadFile(os.Args[2])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	pub, err := base64.StdEncoding.DecodeString(strings.TrimSpace(os.Args[3]))
	if err != nil || len(pub) != ed25519.PublicKeySize {
		fmt.Fprintln(os.Stderr, "the public key is not a base64 ed25519 public key")
		os.Exit(1)
	}
	sig, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(rawSig)))
	if err != nil {
		fmt.Fprintln(os.Stderr, "the signature is not valid base64")
		os.Exit(1)
	}

	sum := sha256.Sum256(payload)
	fmt.Printf("%d bytes, sha256 %s\n", len(payload), hex.EncodeToString(sum[:]))

	if !ed25519.Verify(pub, payload, sig) {
		fmt.Println("REFUSED: this file was not signed by that key")
		os.Exit(1)
	}
	fmt.Println("ok: signed by the given key")
}
