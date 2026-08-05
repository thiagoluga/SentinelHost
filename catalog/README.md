# The engine catalogue

Every ruleset SentinelHost can install, one TOML file each. **Submitting one is a pull
request; approving it is a merge; distributing it is the next release.**

There is no registry fetched at runtime. If the panel downloaded a catalogue from a
server, that server would become the thing worth attacking, and "approved" would mean
"approved unless somebody took over the host". What you can install is what shipped inside
the binary you verified.

## What can be submitted here

**Rulesets for an engine that already exists.** A YARA ruleset is data: the adapter that
runs it is already written and reviewed, so adding one is a manifest and nothing else.
That is most of what is useful — there are dozens of good public rulesets.

**Not new engines.** A tool with its own output format needs a Go adapter to parse it, and
parsing an unfamiliar format *is* code. That goes through `internal/adapter/` and is
reviewed as code. See [`CONTRIBUTING.md`](../CONTRIBUTING.md).

## The manifest

```toml
slug     = "signature-base"
name     = "Neo23x0 signature-base"
homepage = "https://github.com/Neo23x0/signature-base"
license  = "CC-BY-NC-4.0"
kind     = "yara-rules"

# Immutable. A commit SHA or a release asset — never a branch, never `latest`.
url    = "https://raw.githubusercontent.com/Neo23x0/signature-base/<40-hex-commit>/yara/gen_webshells.yar"
sha256 = "<64 hex characters of exactly those bytes>"

# Below the built-in engines on purpose. See "weight" below.
weight     = 0.5
confidence = "heuristic"

summary = "Webshell rules from the signature-base collection."
```

### `url` and `sha256`

The URL says *which review this is*. The digest says *nobody rewrote history or
intercepted the transfer*. Neither is sufficient alone, and a pull request with a branch
URL is rejected by CI rather than by a reviewer remembering.

This is what makes approval mean anything. Approving a ruleset once is worth nothing if
the upstream can change it afterwards — the maintainer would have reviewed one file and
users would run another.

### `weight`

**Community rulesets carry less weight than the built-in engines, and the reason is not
politeness.** The consensus is weighted so that no single engine can quarantine a file on
its own. A ruleset that reached the `confirmed` threshold alone would be able to act on
somebody's site by itself, which is the property the whole design exists to prevent.

Start at `0.5`. Ask for more only with evidence: a false-positive rate measured against
real sites, not an argument that the rules are good.

### `license`

An SPDX identifier. Rulesets are not always permissively licensed —
`signature-base` is CC-BY-NC, which means **it cannot be used commercially**. SentinelHost
records the licence and shows it before installing, because a hosting company installing
a non-commercial ruleset across customer accounts is a licence violation nobody meant to
commit.

## What a reviewer checks

1. **The URL is immutable and the digest matches it.** Verified by downloading it, not by
   trusting the submission.
2. **The rules do what the summary says.** A rule matching `wp-config.php` or `index.php`
   is not a webshell rule — it is a way to make SentinelHost quarantine every site that
   installs it. This is the check that matters, and it is why this is a human review and
   not a CI job.
3. **The licence permits redistribution**, and is stated correctly.
4. **The weight is justified**, and defaults to low.
5. **The upstream is a project, not a gist.** Something with a history, an author who can
   be reached, and a reason to still exist next year.

A submission that cannot be reviewed on those terms is declined. That is not a judgement
about the ruleset — it is that "we approved it" has to mean something.
