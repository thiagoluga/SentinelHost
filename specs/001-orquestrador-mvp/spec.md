# Feature Specification: A multi-engine orchestrator with a consensus verdict (MVP)

**Feature Branch**: `001-orquestrador-mvp`

**Created**: 2026-07-23

**Status**: Draft

**Input**: User description: "An open source tool for shared hosting that orchestrates
existing malware scanners, scans continuously, quarantines confirmed threats, alerts
about suspicions, with a web panel to see and configure everything (engines, the
schedule, webhooks, e-mail alerts)."

## User Scenarios & Testing *(mandatory)*

### User Story 1 - A multi-engine scan with a consensus verdict (Priority: P1)

As the owner of a site on shared hosting, I want the tool to run the scanners available
in my environment over my files and tell me, for each flagged file, whether the threat
is confirmed, likely or merely suspicious — combining the results of all the engines
instead of my having to interpret each one separately.

**Why this priority**: It is the product's core. Without the orchestrated scan and the
consolidated verdict, nothing else (quarantine, alerts, the panel) has anything to show.

**Independent Test**: Run `sentinelhost scan` on a test directory holding a clean
WordPress + synthetic webshell samples. Check that the final report lists the samples at
`confirmed`/`likely` and does not flag the clean core files.

**Acceptance Scenarios**:

1. **Given** a directory with 2+ available engines (e.g. amwscan and
   php-malware-finder), **When** the scan runs, **Then** each engine runs as a
   subprocess, its output is normalized and each flagged file receives a single
   consolidated verdict with a score and a list of votes.
2. **Given** a file flagged by 2 engines with signature confidence, **When** the verdict
   engine computes the score, **Then** the level is `confirmed` (score ≥ 0.9).
3. **Given** a file flagged by only 1 heuristic engine, **When** the verdict is
   computed, **Then** the level is `suspicious` and no automatic action happens.
4. **Given** an engine that fails or hits its timeout, **When** the cycle finishes,
   **Then** the engine shows up as an abstention, the cycle completes with the others and
   the failure appears in the report.
5. **Given** a WordPress core file identical to the official checksum, **When** any
   engine flags it, **Then** the verdict is `clean` (false-positive protection) with the
   reason recorded.

---

### User Story 2 - An automatic, reversible quarantine (Priority: P1)

As the site's owner, I want confirmed threats to be neutralized automatically — without
deleting anything — and I want to be able to restore any quarantined file with one
click, because I am afraid of the tool breaking my site.

**Why this priority**: It is the protective action that justifies running the tool
continuously; the reversibility is what makes the automation acceptable.

**Independent Test**: Force a `confirmed` verdict on a test file; check that it was moved
into the quarantine (restricted permissions, a neutralized extension), that the site is
still functional and that `restore` gives it back byte for byte at its original location.

**Acceptance Scenarios**:

1. **Given** a `confirmed` verdict with the automatic action enabled, **When** the
   quarantine runs, **Then** the file is moved into the vault with its metadata (the
   original path, hashes, permissions, owner, timestamps) and an alert is generated.
2. **Given** a quarantined file, **When** the user clicks restore, **Then** the file
   returns to its original path with the same content and permissions, and the event is
   recorded.
3. **Given** observation mode is on, **When** a `confirmed` verdict happens, **Then** no
   file is moved and the alert says "action recommended".
4. **Given** items in quarantine beyond the retention period, **When** the purge routine
   runs, **Then** only expired items are removed permanently and the purged total is
   recorded.
5. **Given** a file on the user's whitelist, **When** engines flag it, **Then** it is
   never quarantined, but it stays visible in the report.

---

### User Story 3 - Continuous monitoring adapted to the hosting (Priority: P2)

As a user of cheap hosting, I want the tool to keep watching my files without blowing my
account's CPU limits — scanning only what changed, at the time and pace I configure, and
working even if the hosting kills long processes.

**Why this priority**: It turns a one-off scanner into continuous protection; it is the
differentiator against the existing scanners, but it depends on P1 existing.

**Independent Test**: Configure a 1h incremental cycle on a directory with a baseline;
modify 3 files; check that the next cycle scans only the 3 modified ones and completes
within the configured resource limits.

**Acceptance Scenarios**:

1. **Given** an existing hash baseline, **When** the incremental cycle runs, **Then**
   only files that are new or modified since the last cycle are scanned by the engines.
2. **Given** daemon mode, **When** the process is killed by the hosting, **Then** the
   next trigger (a watchdog cron) resumes from the last state without corrupting the
   baseline or the quarantine.
3. **Given** configured limits (nice, a pause between batches, a maximum size), **When**
   any engine runs, **Then** the limits are applied to the subprocess.
4. **Given** cron-only mode, **When** the user finishes the configuration, **Then** the
   tool displays the cron line ready to paste into cPanel.

---

### User Story 4 - E-mail and webhook alerts (Priority: P2)

As the site's owner, I want to be told by e-mail when something is confirmed or likely,
to receive a periodic summary, and to be able to plug in webhooks to integrate with
Slack/Discord/n8n or my own systems.

**Why this priority**: Without notification, continuous protection is invisible; the user
only finds out about the attack when Google flags the site as dangerous.

**Independent Test**: Configure a test SMTP + a test webhook; force a `confirmed`
verdict; check that the e-mail arrives with the correct fields and that the signed JSON
POST reaches the endpoint.

**Acceptance Scenarios**:

1. **Given** SMTP is configured and levels are selected, **When** a verdict at a selected
   level happens, **Then** an e-mail is sent to the recipients with the file, the level,
   the score, the votes and a link to the panel.
2. **Given** the daily digest is enabled, **When** its time arrives, **Then** a single
   e-mail consolidates the period's findings, actions and statistics (sent even with no
   critical incidents, if there are suspicions piled up).
3. **Given** a registered webhook with a secret, **When** a subscribed event happens,
   **Then** a JSON POST is delivered with an HMAC-SHA256 signature header and, on
   failure, retried with exponential backoff (5 attempts).
4. **Given** the "send test" button (e-mail or webhook), **When** it is pressed, **Then**
   a test delivery happens and the result (success/the real error) is displayed right
   away.

---

### User Story 5 - The embedded web panel (Priority: P3)

As a non-technical user, I want a simple panel where I see my site's state (the overview,
findings, the quarantine) and configure everything (engines and weights, the schedule,
limits, alerts, webhooks, verdict thresholds, the whitelist) without editing
configuration files.

**Why this priority**: Everything in the panel is operable through the CLI + the config
file (P1–P2); the panel is the usability layer that widens the tool's audience. Visual
reference: `docs/panel-mockup.html`.

**Independent Test**: Start `sentinelhost serve`, authenticate, walk through the six
areas of the mockup and check that every control reads and writes the real configuration
and that the actions (quarantine, restore, test an alert) really execute.

**Acceptance Scenarios**:

1. **Given** the binary is running, **When** the user opens the panel, **Then**
   authentication is required (a password set on first access; listening on localhost by
   default).
2. **Given** pending findings, **When** the user decides (quarantine / ignore /
   whitelist), **Then** the action executes and the state updates without reloading the
   page.
3. **Given** any configuration change in the panel, **When** it is saved, **Then** it is
   persisted in the configuration file and applied from the next cycle without a manual
   restart.

---

### Edge Cases

- Hosting with no engine available beyond the native ones: the tool operates with
  `wp-checksums` + anomaly heuristics alone and makes it clear in the panel that the
  coverage is reduced.
- A site that is not WordPress (Laravel, a static site, Joomla): `wp-checksums` abstains
  without penalizing the others' score.
- Two simultaneous scan processes (cron + manual): a single-instance lock; the second
  process exits with a clear message.
- A flagged file whose content changes between the scan and the quarantine: a re-hash
  before acting; if it diverges, re-scan instead of quarantining blindly.
- A full disk or no write permission in the quarantine vault: the action becomes a
  critical "could not neutralize" alert instead of failing silently.
- Millions of inodes (sites with runaway caches): honour the default exclusions and the
  depth limit; never walk outside the configured root directory.
- The hosting's SMTP blocking the send: the real error is displayed in the e-mail test;
  the webhook keeps working as an alternative channel.
- Symlinks pointing outside the root: never followed.

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: The system MUST detect which engines are available in the environment
  (probe) and display the reason each one is unavailable.
- **FR-002**: The system MUST run each available engine as an isolated subprocess with
  resource limits and a timeout, collecting the raw output.
- **FR-003**: Each adapter MUST convert its engine's raw output into the versioned
  normalized schema (docs/schema-and-adapters.md), preserving the raw output for
  auditing.
- **FR-004**: The verdict engine MUST consolidate findings by file hash into a single
  verdict with a weighted score, a level (`confirmed`/`likely`/`suspicious`/`clean`) and
  a list of votes and abstentions.
- **FR-005**: The system MUST verify the integrity of WordPress installations against
  the official WordPress.org checksums (the core and, when available, plugins), treating
  a divergence as the maximum-weight vote and an equality as false-positive protection.
- **FR-006**: The system MUST automatically quarantine only `confirmed` verdicts (when
  observation mode is off), reversibly: move it into the vault, remove the execute
  permission, neutralize the extension and record the complete metadata for a restore.
- **FR-007**: The user MUST be able to restore, ignore (once) or whitelist (permanently)
  any flagged file, through the panel and through the CLI.
- **FR-008**: The system MUST keep a hash baseline for incremental scans and run a full
  scan on a separate, configurable schedule.
- **FR-009**: The system MUST operate in daemon mode and in cron-only mode, producing the
  cron line ready for cPanel in the latter.
- **FR-010**: The system MUST send e-mail alerts through configurable SMTP (host, port,
  TLS, credentials, sender, recipients), with a selection of the levels that trigger an
  immediate alert and an optional periodic digest.
- **FR-011**: The system MUST deliver events to registered webhooks as a signed JSON
  POST (HMAC-SHA256 in a header), with an event filter per webhook, retries with
  exponential backoff and a history of the last send.
- **FR-012**: The system MUST offer a test send for e-mail and for each webhook,
  reporting the real result.
- **FR-013**: The system MUST serve an embedded, authenticated web panel with the areas:
  the overview, findings, quarantine, engines, the schedule, alerts and settings — per
  the reference mockup.
- **FR-014**: Every configuration option exposed in the panel MUST be equally editable in
  the configuration file and reflected in both directions.
- **FR-015**: The system MUST record every action (scans, verdicts, quarantines,
  restores, alerts, config changes) in a structured log queryable in the panel.
- **FR-016**: The system MUST update the engines' signatures/rules on demand and on a
  schedule, recording the date per engine.
- **FR-017**: The score thresholds of the verdict levels and the per-engine weights MUST
  be configurable, with safe default values and observation mode recommended in the first
  days.
- **FR-018**: The system MUST prevent concurrent instances (a lock) and MUST re-hash
  files immediately before any quarantine action.

### Key Entities

- **Engine/Adapter**: the external detection engine + the conversion layer; it has a
  slug, a version, an availability state, a weight and the date of its signatures.
- **ScanReport**: one engine's execution in one cycle; the scope, the status, the
  resource usage, the findings.
- **Finding**: one engine's flag about one file; the category, the severity, the
  confidence, the rule, a sanitized snippet.
- **Verdict**: the consolidated decision per file; the level, the score, the votes, the
  abstentions, the action taken, the user's decision.
- **QuarantineItem**: a neutralized file; the metadata for a restore, the retention, a
  reference to the verdict.
- **AlertChannel**: a notification channel (SMTP e-mail, a webhook, Telegram in the
  future); its configuration, its level/event filter, its delivery history.
- **Baseline**: the path→(hash, mtime, size) map the incremental cycles use.
- **Config**: a single file (TOML) with every option; the source of truth shared between
  the CLI and the panel.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: On the test corpus (a clean WordPress + synthetic samples), the consensus
  detects ≥ 95% of the samples as `confirmed`/`likely` with zero `confirmed` false
  positives on official core files.
- **SC-002**: An incremental scan of a 20 thousand-file site with 1% changed completes in
  under 5 minutes within the default resource limits.
- **SC-003**: Every quarantined file is restorable byte for byte; 100% of the round-trip
  tests (quarantine → restore → compare the hash) pass.
- **SC-004**: A non-technical user manages, through the panel alone, to configure an
  alert e-mail and decide about a pending finding in under 5 minutes, with no
  documentation.
- **SC-005**: Alerts for `confirmed` verdicts are delivered (by e-mail or webhook) within
  60 seconds of the verdict.
- **SC-006**: The binary runs on a real cPanel account without root, and the process never
  exceeds the configured CPU/memory limits (verified in the resource tests).

## Assumptions

- The user has at least access to cron (cPanel) and, ideally, SSH; the panel presupposes
  the ability to reach a local port (an SSH tunnel) or an open port.
- The MVP prioritizes PHP/WordPress sites on Linux; other CMSs work with reduced coverage
  (no official checksums).
- The MVP's engines: `wp-checksums` (native), `amwscan`, `php-malware-finder`; `maldet`
  when the environment allows. `wordfence-cli`, `clamav` and Telegram are left post-MVP.
- The panel's interface ships **English** as its base locale, with `i18n` prepared for
  other languages (constitution 1.1.0, Principle VIII — this reverses the pt-BR
  assumption of the original draft).
- The orchestrator's license: MIT; GPL engines only through a subprocess.
