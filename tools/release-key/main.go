// Command release-key generates the ed25519 pair that signs SentinelHost releases.
//
// Run it once, on a machine you trust, and keep the private half the way you would keep a
// passport. `sentinelhost update` verifies a signature against the public half compiled
// into the binary already running, so:
//
//   - Whoever holds the private key can replace the binary on every installation.
//   - Losing it means no existing installation can ever update again. Each would have to
//     be replaced by hand, because a binary only trusts the key it was built with.
//
// Both of those are worth reading twice before pressing enter.
//
//	go run ./tools/release-key             # print a new pair
//	go run ./tools/release-key --self-test # prove the round trip, printing no key
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"flag"
	"fmt"
	"os"
)

func main() {
	selfTest := flag.Bool("self-test", false,
		"generate a throwaway pair, sign and verify with it, and print only the outcome")
	flag.Parse()

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		fmt.Fprintln(os.Stderr, "generating the key:", err)
		os.Exit(1)
	}

	if *selfTest {
		// Proves the format this repository writes is the format it reads, without any key
		// material reaching the terminal, a log, or anyone's scrollback. A generator that
		// produces a key the verifier rejects would only be discovered on a user's first
		// update, which is the worst possible place to find out.
		payload := []byte("a stand-in for a release binary")
		sig := ed25519.Sign(priv, payload)

		encodedPub := base64.StdEncoding.EncodeToString(pub)
		decodedPub, err := base64.StdEncoding.DecodeString(encodedPub)
		if err != nil || len(decodedPub) != ed25519.PublicKeySize {
			fmt.Println("FAIL: the public key does not survive base64")
			os.Exit(1)
		}
		if !ed25519.Verify(decodedPub, payload, sig) {
			fmt.Println("FAIL: a signature from this pair does not verify")
			os.Exit(1)
		}
		if ed25519.Verify(decodedPub, []byte("something else"), sig) {
			fmt.Println("FAIL: the signature verifies against the wrong payload")
			os.Exit(1)
		}
		fmt.Println("ok: a generated pair signs and verifies, and a changed payload is refused")
		return
	}

	fmt.Println("Two halves. They go in different places, and only one is a secret.")
	fmt.Println()
	fmt.Println("1. PUBLIC — repository VARIABLE, named SENTINELHOST_RELEASE_PUBKEY")
	fmt.Println("   Settings > Secrets and variables > Actions > Variables")
	fmt.Println("   Not secret: it is compiled into every release so each can verify the next.")
	fmt.Println()
	fmt.Println("  ", base64.StdEncoding.EncodeToString(pub))
	fmt.Println()
	fmt.Println("2. PRIVATE — repository SECRET, named SENTINELHOST_RELEASE_KEY")
	fmt.Println("   Settings > Secrets and variables > Actions > Secrets")
	fmt.Println("   Paste it there, keep one offline copy, and put it nowhere else.")
	fmt.Println()
	fmt.Println("  ", base64.StdEncoding.EncodeToString(priv))
	fmt.Println()
	fmt.Println("Whoever holds the private half can replace the binary on every installation.")
	fmt.Println("Losing it means no existing installation can ever update again.")
	fmt.Println()
	fmt.Println("Clear your terminal scrollback when you are done.")
}
