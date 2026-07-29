package quarantine

import (
	"crypto/sha256"
	"encoding/hex"
	"hash"
)

// hasher acumula o sha256 do que passa por ele.
type hasher struct{ h hash.Hash }

func newHasher() *hasher { return &hasher{h: sha256.New()} }

func (w *hasher) Write(p []byte) (int, error) { return w.h.Write(p) }

func (w *hasher) hex() string { return hex.EncodeToString(w.h.Sum(nil)) }
