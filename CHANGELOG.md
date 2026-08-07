# Changelog

Notable changes, newest first. Format loosely follows [Keep a Changelog]; versions follow
[Semantic Versioning] once there is a version to follow.

Security fixes say what was exploitable and how, rather than "hardened X". A changelog
entry for a security tool that hides the mechanism is asking the reader to take its word,
and this project's whole argument is that you should not have to.

## v0.1.2

### Added

- **The panel says which version it is running**, in the sidebar, whether or not an update
  exists. On an account with no shell there was previously no way to answer "which version
  are you on" — a question asked far more often than an update happens.
- **The release notes appear in the update banner**, behind a disclosure, with a link to the
  release page. The banner was asking the user to replace the binary that guards their
  account without saying what was in it. The notes are written by whoever cut the release,
  so they are rendered as text and never as markup.

### Fixed

- **First access through the panel was impossible.** v0.1.0 made `POST /api/setup` require
  a token, correctly and with tests — and the setup form was never given a field for it, so
  the only way to complete first access was to send the request by hand. Every test passed,
  because they all exercise the API and the API was right. It took opening the page in a
  browser to see it.

## v0.1.1

### Fixed

- `update --check` now names the release asset alongside its URL. On an account with no
  shell, the person reading that line is usually about to download it by hand on another
  machine, and "which of these files is mine" was the next question every time.

## v0.1.0

The first release. Everything below is what the tool does on the day it became
installable, rather than a list of changes against something earlier.

**What it has been proven against, and what it has not.** One real cPanel account, with no
shell, reached over FTP and a fifteen-minute cron — that is where most of the operational
defects below were found. And a Debian container with the real engines: yara, maldet, PHP
and a live WordPress. It has NOT run on a VPS with root, or on a second hosting provider.
That is the reason for the `0`.

### Security

- **A filename could blind every engine.** The scan scope is handed to yara and maldet as
  one path per line, and a filename on Linux may contain a newline. `x<LF>.php` became two
  lines, neither of which existed, so no engine ever opened the payload — while it stayed
  reachable and executable. Such paths are now refused *and counted*, so the coverage loss
  appears in the report instead of looking like a clean scan (#45).
- **A filename could forge AMWScan's report.** AMWScan prints paths verbatim into a
  line-oriented report, so a name containing `<LF>File: /path/to/wp-config.php` re-attributed
  findings: the payload vanished from the results and a legitimate file was reported as a
  backdoor the user might then quarantine. Report paths carrying control characters are now
  refused and counted (#45).
- **The quarantine could be told to delete a file outside the scanned roots.** A path parsed
  from engine text reached `os.Remove` with nothing asserting it was one the scanner had
  walked. The vault is now bounded to the configured roots (#45).
- **Quarantine could report success while the payload survived.** `os.Remove` unlinks a
  *name*: a second hard link, or a symlink to identical content, meant the file was copied
  to the vault, one name was removed, and the content stayed executable under the other.
  Both are now refused with an explanation (#43).
- **Whoever reached the panel first became its administrator.** `POST /api/setup` was
  guarded only by "has a password been set", and an administrator can point an engine at an
  uploaded file and run it as the account. First access now requires a token printed at
  startup and stored 0600 outside the document root (#44).
- **A page on another origin could act with the owner's session.** `SameSite=Strict` was the
  only defence, and it is a *site* control — the documented install puts the panel inside
  the document root of the site it protects, so any subdomain of the account qualified.
  State-changing requests now require a same-origin signal (#44).
- **The client could choose whether its own session cookie was `Secure`.** The bridge
  forwarded the caller's `X-Forwarded-Proto` and then appended its own; Go reads the first
  (#44).
- **Engine downloads were unpinned.** AMWScan (a PHP program this tool executes) and the
  YARA rules (which decide what gets quarantined) were fetched from a moving branch with no
  integrity check. Both are now pinned to an immutable commit with a verified digest (#40).
- **A file anyone could write disabled scanning for its directory.** An exclusion marker was
  honoured wherever it appeared; writing a file in the document root is the one thing an
  attacker with a webshell has already managed. The marker is now reported, never obeyed
  (#39).
- **Attacker-chosen filenames reached e-mail headers.** A name containing CRLF could forge a
  `Bcc:`. Refused for both transports (#32).

### Fixed

- The baseline advanced for files no engine had opened, so the next cycle treated them as
  unchanged and never scanned them again — for up to a week (#46).
- An unreadable root produced `status: completed` and exit 0, which reads as "scanned
  everything, found nothing" to any monitor (#46).
- Timestamps were stored with a variable-width fraction, so text ordering disagreed with
  the clock and "most recent" was wrong for roughly one write in ten (#28).
- The daily digest could report nothing for a period that had hundreds of findings (#37).
- The panel listed one row per scan cycle rather than per file, and showed evidence
  belonging to a different copy of the same content (#27, #34).
- Findings for identical content at several paths collapsed into one stored row, so a
  verdict could display votes above zero pieces of evidence (#46).
- The panel's status endpoint answered `200` with zeros when it could not read the database
  (#46).
- Sending mail failed against Outlook because only `AUTH PLAIN` was offered (#31).

### Added

- **Mail with no mailbox.** Where the host has a local MTA — most shared hosting — mail is
  delivered through it, with nothing to configure and nothing to authenticate (#32).
- **An engine catalogue.** Community YARA rulesets, proposed by pull request, approved by
  merge, shipped inside the binary. Every entry pins an immutable URL and a digest, and CI
  downloads each one to check the digest is real (#42).
- **A security policy** with a private reporting channel (#41).
- The open tab lives in the URL, so a reload lands where you were (#38).
- Each finding shows what the engine actually saw — the offending snippet and its line or
  byte offset, which were already recorded and never displayed (#24, #29).

[Keep a Changelog]: https://keepachangelog.com/en/1.1.0/
[Semantic Versioning]: https://semver.org/spec/v2.0.0.html
