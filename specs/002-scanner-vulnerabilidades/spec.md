# Feature Specification: The vulnerability and hardening pipeline (prevention)

**Feature Branch**: `002-scanner-vulnerabilidades`

**Created**: 2026-07-23

**Status**: Draft (depends on feature 001)

**Input**: User description: "Also run open source projects that scan the files for
vulnerabilities, to stop people from exploiting the flaws before the malware gets in."

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Vulnerable WordPress components (Priority: P1)

As the owner of a WordPress site on shared hosting, I want to be told when an installed
plugin, theme or the core has a known vulnerability — with the fixed version indicated —
so I can update before someone exploits it.

**Why this priority**: The overwhelming majority of intrusions on shared hosting come in
through an out-of-date plugin; preventing costs less than cleaning up.

**Independent Test**: On a test WordPress with a plugin at a known-vulnerable version,
run `sentinelhost scan --vuln` and check for an `urgent`/`recommended` verdict with the
slug, the installed version, the fixed version and the IDs.

**Acceptance Scenarios**:

1. **Given** a plugin installed at a version the feed considers vulnerable, **When** the
   pipeline runs, **Then** a vulnerability verdict is created per component with a level
   derived from the CVSS/active exploitation, never per file.
2. **Given** a vulnerability with CVSS ≥ 9 or active exploitation, **When** the verdict is
   `urgent`, **Then** an immediate alert fires on the enabled channels (the same channels
   as feature 001).
3. **Given** the same component flagged by two sources (e.g. wf-vulndb and wpscan),
   **When** it is consolidated, **Then** a single verdict lists both sources as votes.
4. **Given** a site with no WordPress, **When** the pipeline runs, **Then** the WP
   adapters abstain silently.

---

### User Story 2 - Dependencies and libraries (Priority: P2)

As a developer hosting a PHP/Composer project (or a theme with bundled JS), I want
lockfiles and known JS libraries checked against public vulnerability databases (OSV.dev,
the FriendsOfPHP advisories, retire.js).

**Independent Test**: A directory with a composer.lock holding a known vulnerable
dependency → a `recommended` verdict with the package, the version and the fix.

**Acceptance Scenarios**:

1. **Given** a composer.lock with a vulnerable package, **When** osv-scanner (or composer
   audit as a fallback) runs, **Then** the finding is normalized as `kind=vulnerability`
   with the `component` block.
2. **Given** an out-of-date bundled JS library (e.g. a jQuery with an XSS), **When**
   retire.js runs, **Then** the finding shows up as `informational` or `recommended`
   according to its severity.

---

### User Story 3 - Hardening the environment (Priority: P2)

As a non-technical user, I want the tool to point out insecure configuration that makes
an intrusion easier — 777 permissions, a publicly reachable `.env`/`.git`/backup, WP_DEBUG
on, the wp-admin file editor enabled — with a guided correction (and an automatic one
when it is safe and reversible).

**Independent Test**: A test environment with 5 misconfigurations planted → all 5 reported
with correction instructions; the ones marked as auto-correctable are corrected and can be
reverted.

**Acceptance Scenarios**:

1. **Given** a file with 777 permissions inside the root, **When** the hardening check
   runs, **Then** a `kind=hardening` finding is created with a suggested correction
   (chmod) and the option to apply it.
2. **Given** an automatic correction was applied, **When** the user undoes it from the
   panel, **Then** the previous state is restored (Principle I).

---

### Edge Cases

- The vulnerability feed/API is down: the pipeline abstains with a "coverage is N days
  out of date" warning; it never blocks the malware pipeline.
- A plugin whose version was modified locally (it matches no release): report it as
  `informational` + suggest the integrity pipeline.
- No outbound network on the hosting: an offline mode with a feed snapshot bundled into
  the binary's update, with the date visible.
- A false "fixed_in" (a wrong feed): the user's decision to silence it per
  component+version, recorded.

## Requirements *(mandatory)*

### Functional Requirements

- **FR-101**: The orchestrator MUST detect the installed inventory (the WP core, plugins,
  themes with their versions; lockfiles; known JS libraries) without depending on an
  external engine.
- **FR-102**: The system MUST query Wordfence's public feed (wf-vulndb) without a token as
  the primary WP source, with a local cache and the date of the last sync visible.
- **FR-103**: The `wpscan` (the user's token), `osv-scanner`, `composer audit` and
  `retire.js` adapters MUST follow the same adapter contract as feature 001 (probe /
  userland install / execution / normalized parse).
- **FR-104**: Vulnerability verdicts MUST be consolidated per component with the levels
  `urgent`/`recommended`/`informational` and MUST NOT trigger a quarantine.
- **FR-105**: `kind=hardening` findings MUST include a suggested correction; automatic
  corrections MUST be reversible and opt-in.
- **FR-106**: The panel MUST gain the "Vulnerabilities" area (the inventory, verdicts per
  component, silencing, history) and the alerts MUST support the new levels in the
  e-mail/webhook filters.
- **FR-107**: The report MUST correlate a `confirmed` malware verdict with open `urgent`
  vulnerabilities on the same site ("the likely way in — update after the cleanup").
- **FR-108**: Updating a component is never done automatically in the MVP; when wp-cli is
  available, the panel MAY offer the command ready to copy.

### Key Entities

- **ComponentInventory**: the installed components (type, slug, version, how it was
  detected) — updated on every cycle.
- **VulnFinding**: a normalized `kind=vulnerability` finding (with the component block).
- **VulnVerdict**: the consolidation per component; the level, the sources, silenced?
- **HardeningFinding**: a misconfiguration + the suggested correction + its state
  (open/corrected/undone/silenced).

## Success Criteria *(mandatory)*

- **SC-101**: In the test environment with 10 vulnerable components planted (WP plugins +
  composer + JS), ≥ 90% are detected with the fixed version indicated, and zero
  quarantines are triggered.
- **SC-102**: An `urgent` vulnerability produces an alert within 60 s of the cycle.
- **SC-103**: A complete vulnerability cycle (the inventory + the feeds) in under 2 min
  for a typical site, honouring the same resource limits.
- **SC-104**: The 5 misconfigurations of the hardening corpus are detected and the
  auto-correctable ones pass the apply→undo round trip.

## Assumptions

- Feature 001 is implemented (the orchestrator, the schema, the alerts, the panel).
- The primary WP source needs no token (wf-vulndb); WPScan is optional with the user's
  token because of the service's license restrictions and limits.
- An outbound network is available by default; the offline mode is documented degradation.
- semgrep and auto-updating components are out of scope for this feature.
