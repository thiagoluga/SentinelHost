# Changelog

Notable changes, newest first. Format loosely follows [Keep a Changelog]; versions follow
[Semantic Versioning] once there is a version to follow.

Security fixes say what was exploitable and how, rather than "hardened X". A changelog
entry for a security tool that hides the mechanism is asking the reader to take its word,
and this project's whole argument is that you should not have to.

## v0.1.11

### Fixed

- **A symlink into ground already covered is no longer reported as a gap.** v0.1.10 began
  naming every skipped symlinked directory, and the first real account showed what that
  meant in practice: `2 directories reached through a symlink were not entered
  (/home1/motel510/access-logs, /home1/motel510/www)`. On cPanel `www` is always linked to
  `public_html`, which is inside the root and is walked under its real name — nothing
  behind it goes unseen. One of those two paths was a genuine gap and the other was the
  standard layout, and the message could not tell them apart. A warning that fires on
  every install is one its reader learns to skip, which is how the real gap next to it
  stops being noticed. Links are now resolved and the two are separated, with the benign
  half still counted under `symlinked_directory_already_covered` — skipped is always
  recorded, but not everything skipped is a hole.

### Changed

- **The release workflow checks that a tag contains what its notes claim**, before
  anything is built or signed: commits on `main` the tag does not contain, the changelog's
  newest heading matching the tag, and no section still called `## Unreleased`. Written
  after v0.1.9 shipped without a fix that had already been merged — built, signed and
  installed on a real account, with the suite green against a tree that did not contain
  the change. The workflow says plainly which of these would not have caught that (none,
  at tag time) and which catches its aftermath (the orphaned `## Unreleased`), because a
  guard described as stronger than it is stops people looking.

## v0.1.10

### Fixed

- **A symlinked directory was counted as one skipped file.** The walk refuses to follow
  symlinks — deliberately, because one pointing outside the configured roots would take
  the scanner into a directory nobody authorised, and on shared hosting possibly into
  another account. That is unchanged. What was wrong is that a skipped symlinked *file*
  and a skipped symlinked *directory* both landed in one bucket, so `skipped: symlink=1`
  meant either "one stray link" or "an entire web-reachable tree that nothing opened".
  Counted, and therefore never silent — but understating the second case by four orders
  of magnitude. `symlinked_directory` is now its own reason, the paths travel with the
  count, and the cycle logs each one with what to do about it.
- **The WordPress search skipped symlinked directories with no count at all.**
  `os.ReadDir` returns entries describing the *link*, so `DirEntry.IsDir()` answers false
  for a symlinked directory and the search dropped it without a trace — meaning an account
  whose site sits behind one would be told "this does not look like a WordPress
  installation". That is the defect the search was written to fix, reintroduced by the fix
  itself. They are now recorded, and the abstention says a WordPress behind one is
  *unexamined* rather than absent.
- **The WordPress search ignored cancellation.** It was one `os.Open` when that was
  harmless; since it learned to search it walks up to fifty thousand directories, so a
  `scan` was slow to answer a Ctrl-C and a cycle could run past its own timeout. Worse, an
  abandoned search reported "no WordPress found", which is the same sentence as "this
  account has none". It now stops when asked and says it was cancelled.
- **The session cookie could not be cleared by a deletion that no longer described it.**
  `setCookie` and `clearCookie` were two hand-written literals and had already drifted —
  the clearing omitted `Secure`. That instance was harmless: the value being cleared is
  empty, a browser matches a deletion on name, domain and path rather than on `Secure`,
  and logout deletes the session server-side first. The shape was not. A cookie is deleted
  only when the deletion describes the same cookie, so adding a `Domain` in one of the two
  places would have made logout stop clearing anything, with nothing failing to say so.
  Both now come from one constructor.

### Fixed — merged before this release, and left out of the last one

These landed in #70, after v0.1.9 had already been tagged: the tag went on the changelog
commit and the fix merged behind it, so the release that was cut and installed on the
validation account contained none of it. The evidence was on screen and went unread — the
deploy printed `wp-includes/version.php does not exist`, which is the OLD message, from
the code this section says was replaced.

- **The WordPress check only ever looked at one directory, and it was almost never the
  right one.** It asked whether the configured root *was* a WordPress — so on a hosting
  account, where the root is the home and the site lives at `public_html/<domain>/`, it
  reported `this does not look like a WordPress installation` and abstained for the whole
  cycle. It now searches at and below every configured root, and scans every installation
  it finds; one account with one WordPress per addon domain is the ordinary shape of
  shared hosting, not an edge case.

  The cost was larger than the missing check. This is the only engine that votes *for*
  legitimacy, and that vote is a veto: a file identical to the official checksum is never
  quarantined however many heuristics flag it. Silent, it left genuine core files to be
  judged by AMWScan and YARA alone — so the gap made false quarantines more likely, not
  just coverage smaller.
- **Only the first configured root was ever passed to it.** A second `roots` entry was
  never looked at. The same "checked one place, reported as if complete", one layer up.
- **One unverifiable site no longer discards the whole report.** The guard against
  comparing against an incomplete core returned an error for the entire engine, so a
  single broken directory could take an account's coverage with it. Each installation is
  now judged on its own, and one that cannot be is **counted** as
  `wordpress_not_verified` rather than vanishing. When *none* can be verified the engine
  still abstains — reporting `completed` with no findings after comparing nothing is this
  adapter's worst possible output.
- **The abstention now says where it looked and how far**, instead of naming a single file
  that does not exist. `searched /home/user to a depth of 6 (412 directories examined)`
  can be checked; `wp-includes/version.php does not exist` made a search that never
  happened look like a definitive result. A search stopped by one of its own bounds says
  which bound stopped it.

## v0.1.9

### Fixed

- **"Installed" was reported without checking whether the engine could run.** The handler
  returned `{"ok": true}` on the strength of `Install` not erroring, which is a different
  statement. They come apart without anything going wrong: installing php-malware-finder
  fetches its YARA rules, and running it needs the `yara` binary — a system package no
  unprivileged account can install. So the panel said "php-malware-finder installed", the
  card underneath still said `unavailable` with the same button, and reloading changed
  nothing because nothing had changed. The install now re-probes and reports what is true:
  installed and working, or installed and still unable to run, with the reason — which is
  the only actionable sentence on that screen.
- **An install button was offered on engines that cannot be installed.** maldet is a system
  package and the WordPress check needs a WordPress to check; both answer
  `ErrNotInstallable`, so two of the three buttons on that screen returned 400 to anyone who
  pressed them. `ProbeResult.Installable` always knew — `doctor` prints it — but it was
  never stored, so the panel could not read it. It is now persisted (schema 4) and the
  button appears only where it can honour the offer.
- **A migration missing from the middle of the record never ran again.** The runner asked
  `MAX(version)` and skipped everything at or below it, which is right only while the
  recorded versions are a contiguous run. It also made a test vacuous: two tests simulate an
  old database by deleting one migration's row and reopening, and once a later migration
  existed, `MAX` came back higher and the migration under test was silently skipped. The
  runner now reads which versions have run, not how far the highest one got.
- **Three buttons in the update flow were unstyled.** `btn-primary` had no rule anywhere in
  the stylesheet and `btn-quiet` was only defined inside the update banner, so "Install it",
  "Restart the panel" and "Check for updates" rendered as the operating system's default
  grey buttons — `rgb(240,240,240)`, `outset 2px`, Arial — in the middle of a dark panel.
  They now use the same `.btn` / `.btn.primary` as every other button. The banner itself had
  no border and no background either: it was written against `--line`, `--panel`, `--bg` and
  `--fg`, none of which are declared. An undeclared custom property invalidates the whole
  declaration, and `border-style` falls back to `none`.

## v0.1.8

### Fixed

- **A wedged panel was reported as a healthy one.** The PHP bridge decided the panel was up
  by opening a TCP connection to its port, which answers whether something *accepts* — not
  whether anything *answers*. A process that is wedged still holds its listening socket, so
  the probe passed, the bridge proxied the visitor's request to it, and the request hung
  until the web server gave up: sixty seconds with no response at all, not even the bridge's
  own 503 page. Measured against the real binary, a panel stopped with `SIGSTOP` reads as
  `UP in 0.00s` to the old probe and `silent in 1.51s` to the new one. The probe is now
  `GET /healthz`, which the panel answers without touching its database, its configuration
  lock or a session — so a panel busy with a scan still replies at once.
- **A port held by a dead-but-not-gone process no longer keeps the panel down forever.**
  Nothing else could clear it: the port is taken, so every start died with *address already
  in use*, a wedged process does not recover, and the account has no shell. The bridge now
  clears it — but only a process id the panel wrote itself and `/proc` confirms is still
  running this binary, `TERM` first and `KILL` only if the port is still occupied two
  seconds later. Anything it cannot prove it owns is left alone and named on the page,
  because a pid file outlives a process that died hard and Linux reuses process ids.

### Added

- `GET /healthz` on the panel, and `serve --pidfile`. Both exist for the bridge; neither
  discloses anything to an unauthenticated caller beyond "this process is serving".

### Upgrading

Install the new binary **before** the new bridge. The bridge starts the panel with
`--pidfile`, and a binary older than this release rejects the flag and exits. In the wrong
order the panel does not come up and the waiting page says
`flag provided but not defined: -pidfile` — install the newer binary and it recovers.

## v0.1.7

### Fixed

- **A configuration that cannot be read back no longer replaces the one that works.** The
  write was already atomic, so the file was never half-written — but nothing checked the
  bytes were parseable. An account was left with a duplicated table, and every start died
  reading it: 54 attempts, each triggered by a visit, with nothing on screen but a page
  that reloaded itself. `SaveTo` now loads the temporary file before the rename, so a bad
  write fails as "the change did not save, and here is why" rather than stopping the tool.
- **The waiting page says why the panel failed**, instead of telling the reader to check a
  log they cannot open. The bridge exists because the account has no shell, so "check
  panel.log" was advice nobody could follow. The last error line is now read and shown.

## v0.1.6

### Fixed

- **The sidebar said `loading…` forever** when the panel was opened straight into any tab
  other than Overview. Nothing was pending: the line is written only by the overview's
  loader, so on `#settings` it kept a placeholder that says "wait" and never resolves. The
  sidebar is chrome rather than tab content, so it is now filled once per page load
  whatever tab you land on — and when that cannot be read, it says nothing rather than
  promising an answer.
- **The sidebar grew taller than the window.** It stretched to match the content column, so
  on a long page such as Settings the `Sign out` button and the last-cycle line sat below
  the fold, reachable only by scrolling a column with nothing in it. It now keeps its own
  height and scrolls independently, and on a narrow window it goes back to sitting above
  the content instead of being trapped in a full-height column.

## v0.1.5

### Added

- **A version block on Settings**, with the running version, the one on disk when they
  differ, the latest release, and when that was last checked. The banner only appears when
  there is something to do; "what am I running" gets asked far more often — usually by
  somebody about to report a problem, on an account with no shell to ask instead.
- **A "Check for updates" button** that really re-asks rather than returning the cached
  answer. The cache exists because the panel checks on every page view and the release API
  rate-limits by IP, but somebody clicking the button wants a fresh answer, and handing
  them an hour-old one with no way to tell would make the button a decoration. The time of
  the check is shown beside it: "no update" read a week after the last successful check is
  a different statement from the same words read a minute after one.

### Fixed

- The sidebar showed the placeholder `orchestrator` instead of the version whenever the
  panel was opened straight into a tab other than Overview, because only the overview's
  loader filled it.

## v0.1.4

### Fixed

- **The panel kept offering an update it had already installed.** It compared the release
  against the version of the *running process*, which after an update is the old one — the
  file changed, the program in memory did not. So installing and then reloading showed the
  same "available" banner, which is indistinguishable from the update having silently
  failed. The panel now asks the binary on disk what version it is, and reports
  `installed and waiting` as its own state, with the restart as the action.
- **Installing twice destroyed the way back.** The second install overwrote the binary with
  itself and moved the old one aside, so the rollback target became the version already
  running. It happened on a real account: both the binary and its `.prev` reported v0.1.3,
  and the v0.1.2 it could have returned to was gone. Installing a version already on disk
  is now refused, with the reason.

## v0.1.3

### Added

- **The panel can restart itself into the version it just installed.** An update replaces
  the file; the process already running is still the old program. The install said so and
  left it there — which, on an account with no shell, is not something the user can act on.
  After a successful install the banner now becomes the action: `Restart the panel`.
  Stopping is the whole restart, because the PHP bridge starts the panel whenever it is not
  answering, so the next visit brings up the new binary. Where there is no bridge, the
  response says the panel stopped and nothing will bring it back, rather than promising a
  restart it cannot deliver.

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
