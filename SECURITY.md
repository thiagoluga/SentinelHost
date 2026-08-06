# Security policy

## Reporting a vulnerability

**Use GitHub's private advisory form:**
[github.com/thiagoluga/SentinelHost/security/advisories/new](https://github.com/thiagoluga/SentinelHost/security/advisories/new)

It is private until we publish it together, and it does not depend on anyone watching an
inbox.

Please do not open a public issue for a vulnerability. Not because disclosure is
unwelcome — it is how this gets better — but because SentinelHost runs with the
permissions of the account it protects, and a public report is a working exploit against
every installation that has not updated yet.

You will get a first reply within **7 days**. If you do not, assume the message was
missed rather than ignored, and say so publicly — a security project that swallows
reports deserves to be called out for it.

There is no bounty. This is an unfunded project, and pretending otherwise would waste
your time.

## What matters most here

SentinelHost runs on shared hosting, as the user whose site it is protecting, and it can
move files. The failure modes worth reporting first:

- **Anything that makes the scanner skip files silently.** A scanner reporting "0
  findings" while having scanned nothing is worse than no scanner, because it manufactures
  confidence. Exclusions that can be triggered by an attacker are in this class — see
  D-050 in [`DECISIONS.md`](DECISIONS.md) for one we shipped and fixed.
- **Anything that reaches the engine downloads.** The scanner executes what it downloads,
  and a YARA ruleset decides which of the user's files are quarantined. A hostile ruleset
  needs no code execution to destroy a site: SentinelHost would do it, on schedule.
- **Anything that turns the quarantine into deletion.** The vault exists so an action is
  reversible. A path that removes a file without a restorable copy is a data-loss bug with
  a security shape.
- **Anything reachable through the PHP bridge.** `contrib/php-bridge/` puts an
  administrative panel on a public URL. It proxies to the loopback, and it must not become
  a way to reach anything else.
- **Panel authentication and session handling.** The panel's password is the only thing
  between the internet and a tool that can move files.

## What is already known, and is not a finding

- **The bridge exposes the panel on a public URL.** That is what it is for, on hosting
  with no shell. The README says to restrict it by IP as well, and the panel's password is
  not decoration.
- **The binary must live outside the document root.** If it does not, the install is
  wrong, and the documentation says so.
- **maldet cannot be installed without root.** SentinelHost abstains rather than pretending
  to have run it.
- **`curl | sh` is how the installer is documented.** The checksum verification inside it
  is not optional, and signed releases are tracked as work still to do.

## Supported versions

The latest `0.x` release is the only supported version. There is no long-term support
branch and no backporting: with one maintainer, promising either would be a promise
broken quietly.

`0.x` is deliberate. The tool has been validated against one real cPanel account and a
Linux container; it has not yet run on a VPS with root, or on a second hosting provider.
Until it has, treat it as something that finds problems for you to look at rather than
something to leave unattended over files you cannot replace.

## What we will do

- Reply within 7 days.
- Agree a disclosure date with you rather than announcing one.
- Credit you by whatever name you choose, or not at all.
- Write down what was wrong and why it happened in [`DECISIONS.md`](DECISIONS.md),
  including the reasoning that produced it. That file already records defects this project
  shipped and the arguments that made them look correct at the time; a report from you
  would be recorded the same way.
