# Releasing

## The key

`sentinelhost update` verifies an ed25519 signature against a public key **compiled into
the binary already running**. That is the whole security model, so the key matters more
than anything else here.

Generate it once, offline:

```bash
go run - <<'EOF'
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"fmt"
)

func main() {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	fmt.Println("PUBLIC (repository variable SENTINELHOST_RELEASE_PUBKEY):")
	fmt.Println(base64.StdEncoding.EncodeToString(pub))
	fmt.Println()
	fmt.Println("PRIVATE (repository secret SENTINELHOST_RELEASE_KEY):")
	fmt.Println(base64.StdEncoding.EncodeToString(priv))
}
EOF
```

- The **public** half goes in a repository *variable* named `SENTINELHOST_RELEASE_PUBKEY`.
  It is not secret; it is compiled into every release so each one can verify its successor.
- The **private** half goes in a repository *secret* named `SENTINELHOST_RELEASE_KEY`, and
  nowhere else. Keep an offline copy somewhere you would keep a passport.

**Losing the private key means no existing installation can ever update again.** They would
each have to be replaced by hand, because a binary only trusts the key it was built with.
That is the cost of the property that makes this safe, and it is worth stating before it
happens rather than after.

## Cutting a release

```bash
git tag v0.1.0
git push origin v0.1.0
```

The workflow then, in order: runs the suite **on the tagged commit** — a tag can point
somewhere branch protection never saw — builds for `linux/amd64` and `linux/arm64` with the
public key compiled in, signs each asset, **verifies each signature against that same public
key**, and publishes.

That verification step exists because the alternative is discovering a key mismatch on a
user's first update, which is the worst possible place to find it.

A build with no public key **fails**. A release that cannot verify its successor would
leave every installation of it permanently unable to update, and it would look completely
normal until someone tried.

## What a user does

```bash
sentinelhost update --check   # reports, changes nothing — this is what belongs in cron
sentinelhost update           # asks, then replaces
sentinelhost update --rollback
```

Never on a schedule and never as a side effect. A security tool that replaces itself
unattended on shared hosting behaves the way the things it hunts behave, and from the
outside the user cannot tell the difference.

The previous binary is kept beside the new one as `sentinelhost.prev`, and rollback swaps
them rather than overwriting — somebody who rolls back by mistake has not destroyed the
version they were on.
