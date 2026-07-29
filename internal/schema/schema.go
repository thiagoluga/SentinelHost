// Package schema defines SentinelHost's normalized result schema.
//
// It is the only language the verdict engine understands. Adapters convert
// their engine's raw output into these types; the verdict engine never knows
// about a specific engine (Principle VI of the constitution).
//
// Source: docs/schema-and-adapters.md.
package schema

// Version is the normalized schema version this package implements.
//
// Adapters declare which version they emit; the orchestrator refuses to load an
// object from a higher major version than its own.
const Version = "1.0"

// MaxMatchedContentBytes caps the snippet that triggered a rule. The
// constitution requires that malicious content is never re-served: the snippet
// is truncated and sanitized before it leaves the adapter.
const MaxMatchedContentBytes = 512
