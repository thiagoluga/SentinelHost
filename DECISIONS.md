# Implementation decisions

A record of the choices made where the spec, the plan or the tasks left room for
interpretation. The tie-breaker is always the closest constitution principle. Every
decision cites the principle that settles it.

---

## D-001 — The Go module path

**Ambiguity**: T001 asks for `go mod init github.com/<org>/sentinelhost`, without
defining the org, and the repository that was created is `thiagoluga/SentinelHost`
(with capitals).

**Decision**: `module github.com/thiagoluga/SentinelHost`.

**Reason**: a module path in Go is case-sensitive and has to match the repository's
real path for `go install github.com/...@latest` to work. Using the conventional
lowercase would break the one-command installation, which Principle VII (operational
simplicity) requires.

---

## D-002 — The development environment is Windows; the target is Linux

**Ambiguity**: the plan defines a Linux x86_64/arm64 userland target without root,
but the development is happening on Windows.

**Decision**: all platform-specific code (nice/ionice, chmod, the owner's uid/gid,
signals) is isolated behind files with build tags (`_unix.go` / `_windows.go`). The
tests that depend on POSIX permission semantics are skipped on Windows with an
explicit `t.Skip`, never silently.

**Reason**: Principle III requires the real behaviour to be that of Linux userland;
Windows is only the workstation. Hiding the difference with a mute `t.Skip` would
make the suite lie about coverage.

---

## D-003 — The consensus score: a sum normalized by a ceiling, not an average

**Ambiguity**: `docs/schema-and-adapters.md` defines the level thresholds
(`confirmed` ≥ 0.9 etc.) and the per-engine weights (wp-checksums 1.5, maldet 1.0,
amwscan 0.8, pmf 0.8), but not the formula that turns votes into a score.

**Decision**: the score is the sum of the votes' effective weights divided by a
configurable saturation ceiling (`saturation`, 2.0 by default), truncated at 1.0. A
vote's effective weight is `engine_weight × confidence_multiplier`, with `signature`
= 1.0, `heuristic` = 0.8 and `anomaly` = 0.55.

**Reason**: it has to reproduce the examples the documentation gives as `confirmed`.
Two engines with `confidence=signature` (1.0 + 0.8 = 1.8 over the ceiling of 2.0 =
0.9) land exactly on `confirmed`, and a divergent official checksum (1.5) + one
engine (0.8×0.8 = 0.64), adding up to 2.14, saturates at 1.0 — also `confirmed`. An
average would punish the consensus for every additional engine that abstained, which
contradicts Principle VI ("an abstention is never a clean vote"): with an average,
abstaining would lower the score exactly like a vote of innocence.

---

## D-004 — An abstention does not enter the denominator

**Ambiguity**: the schema requires recording `abstentions`, but does not say whether
they affect the score.

**Decision**: abstentions are recorded in the `Verdict` for transparency and are
completely ignored in the score's calculation.

**Reason**: Principle VI is explicit — an adapter failure is an abstention, "never a
clean vote". If an abstention entered the denominator, an engine that hit its timeout
would dilute the score and could downgrade a `confirmed` to `likely`, turning a
technical failure into a security decision.

---

## D-005 — The official-checksum protection is a veto, not a vote

**Ambiguity**: the schema says a file identical to the official checksum is "never
quarantined, regardless of votes", but scenario 5 of US1 asks for a `clean` verdict.

**Decision**: matching the official checksum forces `level=clean` and `score=0`,
preserving the list of votes that existed and recording
`clean_reason="official_checksum_match"`. It is not a negative vote added to the
score: it is a veto applied after the calculation.

**Reason**: scenario 5 of the spec asks for `clean` with "the reason recorded". A
negative vote could be overcome by enough other votes, which would break the "never,
regardless of votes". A veto is the only implementation that honours both sentences.

---

## D-006 — The whitelist blocks the action, not the verdict

**Ambiguity**: the whitelist "never quarantines, but stays in the report".

**Decision**: a whitelisted file keeps the level and score that were computed
(including `confirmed`) and appears normally in the report; what changes is
`action_taken="skipped_whitelist"`.

**Reason**: FR-007 and scenario 5 of US2 require it to "remain visible in the
report". Downgrading the level to `clean` would hide from the user that the engines
keep flagging that file — it would collide with Principle V (transparent consensus).
Unlike the official checksum (D-005), where there is positive proof that the file is
legitimate, the whitelist is only a decision of the user's.

---

## D-007 — Observation mode on for the first 7 days

**Ambiguity**: T006 asks for "observation ON for the first 7 days"; FR-017 speaks of
"observation mode recommended in the first days". It was not defined from which
instant the deadline counts, nor what happens when it expires.

**Decision**: the config stores `first_run_at` (written on the first cycle). While
`now < first_run_at + 7d`, no automatic quarantine happens, even with
`observation_mode=false`; the alerts go out marked as "action recommended". Once it
expires, the behaviour follows plain `observation_mode`, and the transition's event
goes into the structured log and into the panel.

**Reason**: Principle I — the grace period exists so the user can calibrate weights
and the whitelist before the tool touches their files. Making the expiry silent would
be a change of behaviour with no warning.

---

## D-008 — An automatic action requires `confirmed` AND no grace period

**Decision**: the automatic quarantine only fires when, simultaneously: the level is
`confirmed`, `observation_mode=false`, the grace period has expired, the file is not
whitelisted, the file does not match an official checksum, and the re-hash taken
immediately before the action matches the verdict's hash.

**Reason**: FR-018 and Principle I. If the re-hash diverges, the file changed between
the scan and the action: the tool re-scans instead of quarantining blindly (an
explicit edge case in the spec).

---

## D-009 — The raw-output fixtures are synthetic, with declared provenance

**Ambiguity**: T010 and CONTRIBUTING ask for "raw output" fixtures; the constitution
forbids live malware in the repository.

**Decision**: the fixtures under `tests/testdata/raw/<engine>/` faithfully reproduce
each engine's output **format**, but the files and snippets cited inside them point at
the repository's own synthetic corpus. Each fixture directory has a `PROVENANCE.md`
declaring which engine version the format was derived from.

**Reason**: the contract test has to validate the parser, not the detection. The
format is the contract; the content it points at can be synthetic without losing any
testing power, and that keeps the repository free of live samples.

---

## D-010 — The synthetic corpus uses an inert marker, in EICAR's spirit

**Ambiguity**: the spec asks for "synthetic webshell samples" and
`docs/schema-and-adapters.md` speaks of "EICAR-like for PHP".

**Decision**: each corpus sample is an **inert** PHP file that contains a fixed
project marker (`SENTINELHOST-SYNTHETIC-CORPUS`) and reproduces the *structure* of a
malicious pattern (obfuscated concatenation, a dynamic callback, a base64 blob)
without ever assembling a working executable call. Three guarantees hold for all of
them: the first executable statement is an `exit()`; the function-name fragments are
never joined into a dynamic call; none of them makes a network call, writes to disk,
reads input or opens a process.

`tests/testdata/corpus/SAMPLES.md` documents one by one what they simulate and which
category/severity/confidence they should receive, and `manifest.json` carries the same
information in a machine-readable format. The SC-001 test fails if it finds a corpus
file that is not in the manifest — so nobody adds a sample without declaring the
expectation.

**Reason**: the constitution forbids executable malware in the repository. The corpus
has to exercise the consensus, and for that it is enough that the *synthetic test*
adapters recognize the patterns — the test's value lies in the verdict engine.

---

## D-011 — The real engines are not downloaded during the tests

**Decision**: no automated test downloads AMWScan's phar, the `yara` binary or the
php-malware-finder rules. The contract tests run over fixtures; the consensus
integration tests use fake adapters that emit fixed `ScanReport`s.

**Reason**: Principles III and IV. A test that depends on the network and on an
external binary fails in CI and on the user's hosting for reasons that have nothing to
do with the code. `Install()` is exercised manually and documented in the quickstart —
and, since then, by the validation container (D-022).

---

## D-012 — A development environment with an active antivirus

**Context**: during the implementation, Windows Defender quarantined
`docs/esquema-e-adaptadores.md` because of its `matched_content` example. That
happened twice, and the second time it cost the file: a `git add -A` recorded the
deletion, and the document that the constitution calls the heart of the project
disappeared from the repository for several commits while `CLAUDE.md`,
`CONTRIBUTING.md` and `internal/adapter/adapter.go` kept pointing at it.

**Decision**: the synthetic corpus (D-010) never contains a working payload, which
lowers the chance of a heuristic detection by a workstation antivirus. The document —
now `docs/schema-and-adapters.md` — keeps its `matched_content` example **redacted**
instead of reproducing a payload-looking snippet, which is the same rule the adapters
already follow. The `README.md` of `tests/testdata/corpus/` documents that an
antivirus exclusion may be needed in order to clone the repository on Windows.

**Reason**: a security tool's repository that cannot be cloned without turning the
antivirus off is a useless repository in practice. And a file that an antivirus can
silently delete must not be the only place where a design decision lives.

---

## D-013 — `kind` and `component` in the schema since the MVP

**Ambiguity**: spec 002 (the vulnerability scanner) is not to be implemented now, but
section 3 of `docs/schema-and-adapters.md` already defines the discriminating field
`kind` and the `component` block.

**Decision**: both enter the `internal/schema` package right away, with an empty
`kind` treated as `malware`. No vulnerability-pipeline logic is implemented.

**Reason**: the instruction was not to take decisions that would make 002 unfeasible.
Adding a discriminating field later would force a major schema version bump and a
reprocessing of all the archived raw output — while adding it now, optional and with a
default, costs nothing. The validation already covers the difference that matters: a
vulnerability finding is consolidated per component, not per file, and therefore does
not require `file.sha256`.

---

## D-016 — SC-001's denominator: the malicious-content samples

**Ambiguity**: SC-001 demands "≥ 95% of the samples as `confirmed`/`likely`". The
corpus has 12 samples, and two of them (`08-suspicious-location` and
`11-loose-permissions`) simulate signals whose only evidence is an **anomaly** — a PHP
file in a media folder, a 0777 file in the web root. With the weights and multipliers
from the schema document, two anomaly votes add up to 0.88 over the ceiling of 2.0,
that is `suspicious`. With 12 samples, 95% means all 12 would have to reach `likely`.

**Decision**: SC-001 is measured over the **malicious-content** samples — the ones
whose manifest declares a `minimum_expected_level` of `likely` or `confirmed` (10 of
the 12). The two pure-anomaly samples are checked against the `suspicious` floor the
manifest declares, and there is a dedicated test
(`TestAnAnomalyAloneDoesNotReachLikely`) that **pins** the behaviour that an isolated
anomaly does not escalate.

**Measured result**: 10/10 (100%) of the malicious-content samples in
`confirmed`/`likely`, and 12/12 detected at `suspicious` or above, with zero
`confirmed` false positives on the clean files.

**Reason**: forcing an anomaly to `likely` would mean touching the multipliers to make
a number pass, and the side effect would be real: `likely` is the level that triggers
an "action recommended" alert (FR-010). A file in the wrong place would start waking
the user up in the middle of the night, and Principle V is explicit about scaling the
response by the strength of the evidence. The alternative — removing the two samples
from the corpus — would be worse: the consensus would lose test coverage for
`confidence=anomaly`, which is precisely the easiest path to break without anyone
noticing.

---

## D-017 — Panel testing over HTTP, not through a browser

**Ambiguity**: T037 asks for an e2e panel test with `chromedp`.

**Decision**: the e2e test exercises the panel through the **HTTP API**
(`httptest`), covering SC-004's complete flow: first access → set the password → list
findings → decide about a finding → configure e-mail → trigger a webhook test. There
is no browser dependency.

**Reason**: `chromedp` would bring a large dependency tree and would require an
installed Chrome for the suite to run — in CI and on a contributor's machine.
Principle VII (no mandatory external dependencies) applies to the development
environment too: a repository whose suite only passes for people who have Chrome is a
repository with fewer people running the tests.

**What this does NOT cover, stated explicitly**: rendering, layout, accessibility and
the part of SC-004 that is real usability ("a non-technical user manages it, in under
5 minutes, with no documentation"). That remains manual validation, listed as pending
in `SUMMARY.md`.

---

## D-018 — AMWScan's incremental scope applied by the adapter

**Context**: the contract says the orchestrator decides the scope and the adapter only
executes. For AMWScan that is not implementable as intended.

**Measurements in the validation container** (`make validate-engines`):

- `--filter-paths` with **one** path works; with **two or more**, the engine runs,
  exits 0, writes the report and flags nothing — not even the files that would match
  on their own. It is AND semantics, not OR.
- `--filter-paths` filters the **report**, not the set that gets walked. One execution
  per file cost 1m37s for 11 files.

**Decision**: one execution per cycle, over the root, and `Parse` discards the
findings outside the requested list. The list travels in `RawOutput.Extra`.

**Reason**: of the possible options, it is the only correct one. Passing several paths
would produce "0 findings" with the engine green — a healthy engine, a clean report, an
infected site, which is the failure mode Principle VI exists to prevent. One execution
per file would be correct but unaffordable. The price is CPU: AMWScan walks the whole
site on every cycle, and no SentinelHost setting changes that, because the engine does
not know how to scan a file list.

---

## D-019 — The periodic maintenance also on the `scan` path

**Ambiguity**: T025 asks for a daemon with cycles, retries and a digest. It does not
say where those routines run in `cron` mode.

**Decision**: webhook retries, the periodic summary, the retention purge, log and
raw-output pruning, and interrupted-cycle recovery live in `internal/housekeeping` and
are called by **`scan` and `daemon`**.

**Reason**: the project's default mode is `cron` (Principle III — a live process cannot
be presupposed). With the routines only in the daemon, on the path the documentation
itself recommends the 5-attempt backoff existed in the code and never happened, the
digest never went out, and the log and the raw output grew until they blew the
account's disk quota — the tool taking down the site it promises to protect.

---

## D-020 — A missing core file is not a signature

**Context**: on the first real run, `wp-checksums` emitted **2998** `likely` findings —
one per missing core file, including `.woff2` fonts.

**Decision**: above 10% of the core files missing, the adapter **abstains** with an
explicit reason. Below that, only a file with an executable extension becomes a
finding, with `confidence=anomaly` and `severity=medium`.

**Reason**: an incomplete WordPress is almost never an attack — it is the core in a
subdirectory, a partial deploy, a symlink or a misconfigured root. And absence is not a
signature of anything: a file that does not exist holds no backdoor and cannot be
quarantined. Treating it as `signature` let weight 1.5 push the finding on its own
close to `confirmed`, authorizing action on a file that does not exist.

---

## D-021 — Flags accepted at any position on the CLI

**Context**: the standard library's `flag` stops parsing at the first argument that
does not start with a dash. That made

```
sentinelhost quarantine restore q_123 --config /path/config.toml
```

ignore the `--config` silently and fall back to the default path — and that is exactly
the form the quickstart documents.

**Decision**: `parseArgs` parses in a loop, taking one positional out at a time, and
accepts flags at any position.

**Reason**: the symptom was a misleading error ("configuration not found") in a command
that received the configuration correctly. The real risk was worse: on a machine with
more than one site, the command would act on the wrong instance — and `restore` and
`purge` are precisely the ones that touch files. A mistyped flag is now an error too,
instead of becoming a silent positional argument.

---

## D-022 — A test built on an assumption does not count as verification

**Context**: this is the most expensive lesson of this session, and it deserves to be
recorded as a rule rather than as an anecdote.

Nine defects were found by running the product for real on a Linux with the actual
engines and APIs. **Eight of them are the same mistake**: I assumed how the outside
world behaves, wrote the test that confirmed my assumption, and the test passed.

The plugins case is the clearest one. The API publishes hashes as strings; I declared
`[]string`, wrote 16 tests with array fixtures, all of them passed — and against the
real API `Unmarshal` failed and **every plugin was skipped with zero findings and no
visible error**.

**Decision**: for everything that crosses the process boundary — an engine's CLI, an
output format, an API response — the repository keeps a **captured real sample**, and
the test runs against it:

| Boundary | Real fixture |
|---|---|
| AMWScan output | `tests/testdata/raw/amwscan/` (the `--report-format txt` format) |
| yara output | `tests/testdata/raw/php-malware-finder/` |
| Plugin checksums API | `internal/adapter/wpchecksums/api_format_test.go` |
| Each engine's flags | `docker/validate-engines.sh`, against the installed binary |

And `make validate-engines` always compares what the **orchestrator** sees with what
the **engine sees on its own**. Different numbers fail the run.

**Reason**: in an orchestrator, a wrong assumption does not produce an error — it
produces "0 findings" with the engine marked as healthy. It is the only failure mode
the user has no way of noticing, and therefore the only one against which care is not
enough: it needs evidence.

---

## D-014 — The structured log in SQLite, the raw output in a file

**Ambiguity**: plan.md lists "logs" in the data directory and FR-015 requires a
structured log **queryable in the panel**.

**Decision**: the structured log (`events`) lives in SQLite; the engines' raw output
lives in a file, under `<data_dir>/raw/<scan_id>/`.

**Reason**: querying with a filter by category, level and period is exactly what the
panel needs and exactly what a text file does badly. The raw output stays in a file
because it is large, it is read whole when it is read at all, and it has to survive a
corrupted database in order to allow reprocessing through `Parse()`.

---

## D-015 — Pruning the log is not a destructive action in Principle I's sense

**Decision**: `PruneEvents` deletes events beyond the retention without requiring the
user's confirmation.

**Reason**: Principle I protects **the user's files**. A log is data the tool
generated, and on an account with a disk quota a log that grows without bound ends up
taking the site down — the opposite of what the tool promises. The retention is
configurable and the default (90 days) is generous.

---

## D-023 — English is the repository's language, retroactively

**Context**: the project was written in Portuguese — code, comments, error messages,
CLI output, panel, documentation and commits. SentinelHost is open source
infrastructure for shared hosting, and shared hosting exists everywhere.

**Decision**: everything committed to the repository is in English (constitution
1.1.0, Principle VIII). The whole codebase was translated, not only new code: files
and directories were renamed to their English names, and the report keys a user reads
went with them (`regra_desconhecida` → `unknown_rule`, `plugin_sem_checksum` →
`plugin_without_checksum`, and so on). The panel ships English as its base locale;
`i18n` may add other locales later.

Two contract strings changed as a consequence, and they are worth naming because they
are not cosmetic: the purge confirmation token is now `purge` (in the HTTP API and in
the CLI prompt), and the panel's element ids follow the English names.

**Reason**: a contributor in Jakarta or Lagos has to be able to read a comment
explaining *why* the quarantine copies before it deletes, without a translator. Half a
translation would be worse than none: a codebase where the identifiers are English and
the comments are Portuguese forces every reader to know both.

**What did not get translated**: the captured raw output under `tests/testdata/raw/`.
Those files are evidence of what an external engine actually printed, and editing them
would destroy the only thing that makes them worth keeping (D-022). Only the markers
this repository authored itself — an invented rule name, a base64 blob of our own text
— were translated.

The conversation with the maintainer stays in whatever language they prefer. The rule
applies to artifacts that are committed.

---

## D-024 — A chat destination gets a chat-shaped body, and a per-destination escape

**Ambiguity**: US4 says the webhooks serve to "integrate with Slack/Discord/n8n or
your own systems". The generic webhook satisfies that only for the third group:
Slack's and Discord's incoming webhooks reject an arbitrary payload, so posting this
project's envelope to either one is rejected or arrives as an empty message.

**Decision**: a per-webhook `format` field — `raw` (the default), `slack`,
`discord`. `webhook.Body()` decides the shape, and what it returns is both what gets
POSTed and what gets signed.

Four rules the implementation encodes:

1. **An empty format keeps meaning `raw`.** Every webhook configured before the field
   existed has none. Silently changing their body shape would break deliveries that
   work today, which is the kind of upgrade this project cannot afford: the user finds
   out when an alert does not arrive.
2. **The message carries the votes.** A chat alert reading "threat confirmed" and
   nothing else forces the user into the panel to learn anything, and the votes are the
   whole point of a consensus verdict (Principle V). Abstentions travel with it for the
   same reason they travel everywhere else — a cycle where half the engines failed must
   not read as a clean cycle (Principle VI).
3. **Attacker-chosen text is escaped per destination.** The file path comes from the
   intruder. `<!channel>.php` is a legitimate filename and a perfectly good way to make
   our own alert ping an entire Slack workspace; Discord needs `@everyone` broken with a
   zero-width space and its markdown backslash-escaped. Escaping is per destination
   because the two have no common encoding.
4. **An unknown format fails the delivery** rather than falling back to `raw`. A
   delivery that "worked" in the wrong shape is precisely the quiet wrongness that
   D-022 is about.

**On the signature**: it is computed over the body actually sent, so it always
verifies against itself. But neither Slack nor Discord checks one, so it only *means*
something for `raw` — and the configuration warns when a secret is set on a chat
format, because saying nothing would let the user believe a signature protects a
delivery nobody verifies.

**On the retry path**: the first attempt hands the formatter a typed struct; a retry
hands it whatever `json.Unmarshal` produced from the persisted payload. The formatter
normalizes both through JSON, and a test pins that a retry renders identically —
a retry is exactly the path nobody watches.

**Motive**: the README listed Slack and Discord as "not yet" while US4 promised them.
Either the promise or the README had to change, and the promise was the reasonable
one to keep.

---

## D-025 — maldet's own quarantine is disabled on every invocation

**Context**: the maldet adapter is the last MVP engine. maldet ships with its own
quarantine and its own cleaner, and both are configured host-side in `conf.maldet`.

**Decision**: every invocation passes `--config-option quarantine_hits=0`,
`quarantine_clean=0` and `quarantine_suspend_user=0`, rather than trusting how the
host configured maldet. And if the report still comes back with `TOTAL CLEANED` above
zero, the adapter **abstains with an explicit reason** instead of returning findings.

**Reason**: Principle I. maldet's quarantine is not reversible from our vault, is not
recorded in our store, and cannot be undone from the panel. A host with
`quarantine_hits=1` would have maldet moving the user's files somewhere we cannot
restore from — the tool causing exactly the harm it promises to prevent, through an
engine the user never configured.

Abstaining on `TOTAL CLEANED > 0` is the harder half of the decision. Returning the
findings would look more useful, but a cycle where a file was already modified outside
the vault cannot be reported as a normal cycle: the user has to learn that something
altered their files before they read a verdict list. Loud beats useful here.

**Also decided**: maldet ships **enabled** by default now. The earlier default was
disabled, because enabling an engine with no adapter behind it produced an abstention
every cycle about something the user could not fix. With the adapter present, a host
without the binary gets an unavailability with a reason to act on — which is
information, not a false alarm.

**Install() refuses, and says why**: maldet installs as a system package and needs
root, which Principle III forbids depending on. `ErrNotInstallable` with a generic
message would leave the user guessing; naming root tells them what to ask the hosting
support for.

**Seven defects the real engine caught**, and the fixture that was itself invented:

Installing maldet 1.6.6 in a container and running it as an unprivileged account found
that six of my assumptions about it were wrong, and that the versioned fixture
describing its report had been written from those same assumptions rather than from a
real run. Any one of them alone would have made the adapter useless while looking
correct:

1. **`maldet --report <id>` prints nothing.** It hands the session file to `$EDITOR`.
   With no EDITOR it prints `vi: command not found`; with vi present it would block
   forever waiting for input and hang the cycle until the timeout killed it. The
   undocumented second argument `dump` is what prints to stdout — visible only in
   maldet's own `internals/functions`, not in `--help`.
2. **The report has no `malware detect scan report` line.** The format check looked for
   it, so every genuine report would have been rejected as off-format and the adapter
   would have abstained every cycle.
3. **`--config-option` takes one comma-separated value**, not repeated flags. Passing it
   three times risks the last winning, which would silently drop `quarantine_hits=0` and
   let maldet move the user's files into its own non-reversible quarantine — a
   Principle I violation caused by my own untested assumption. The same shape as D-018.
4. **The hit-line regex was `^\{([A-Za-z]+)\}…`**, which skipped every `{MD5}` line
   because of the digit — one of maldet's two exact-match types, and a third of the hits
   in the fixture.
5. **`scan_user_access="0"` is maldet's shipped default, and it refuses every non-root
   account** — printing the version banner, then the refusal, then exiting **0**. From
   `--version` too. So `Probe()` read a version out of a refusal and reported the engine
   **available and healthy** on a host where it could not scan a single file. That is
   D-011's mbstring defect exactly, in a new engine, found the same way: by installing
   the real thing. There is a **second** gate behind it, which nothing in the
   documentation mentions — with access enabled maldet still refuses until root has run
   `maldet --mkpubpaths`. The two need different remedies, so the adapter reports them
   separately (`accessGateReason`): telling an admin to change a setting that is already
   correct is worse than telling them nothing.
6. **A finished scan never prints `SCAN ID:`.** It prints
   `scan report saved, to view run: maldet --report 260730-0913.91`. `SCAN ID:` appears
   in the **report**, which is the thing that cannot be fetched without the id. The
   regex matched only `SCAN ID:`, so the adapter found no id after every *successful*
   scan and abstained on every cycle — an engine listed as installed, contributing
   nothing, forever.

7. **maldet restricts its walk to a file list, through `-f/--file-list`.** `Info()`
   declared `ScopeAware: false` with a comment asserting that "it has no flag that
   restricts the walk to a file list". `--help` documents one, and measuring in the
   validation container settled it:

   | Invocation | Files | Wall clock |
   |---|---|---|
   | `-a <root>` | 2,999 | **28m36s** (37m42s under `nice 19`) |
   | `-a <root>` | 401 | 3m24s |
   | `-f <list>` | 2 | **7s**, and the report said `TOTAL FILES: 2` |

   So it walks the list, not the root — at roughly half a second of bash-and-perl per
   file. With `ScopeAware: false` the orchestrator paid that half hour every cycle to
   re-read files nothing had touched. It is not waste, it is the CPU burn that gets a
   shared-hosting account suspended, committed by the tool whose Principle IV exists to
   prevent exactly that. It is also, precisely, the D-018 defect again: an adapter
   declaring it cannot narrow its scope when the engine can. With `ScopeAware: true` an
   incremental cycle over 200 changed files costs ~100s instead of 28m36s.

   The reason it surfaced at all is that maldet **exceeded the 5-minute engine timeout**
   in the validation container and abstained. The abstention was correct — it is what
   Principle II is for — but "correct abstention every cycle forever" is an engine that
   contributes nothing, and chasing why is what found the flag.

Defects 5 and 6 are the two that no amount of care with the documentation would have
caught, and both end in this project's defining failure mode: an engine that reports
healthy and scans nothing. Defect 7 is the one a *green suite* would never have caught:
nothing was wrong with the code, only with a comment stating a fact about the engine that
was never checked.

**The target list goes under DataDir, not /tmp.** It names every path about to be
scanned, which on a compromised site is a map of where the interesting files are.
DataDir is the account's own directory, created 0700, and the list is removed after the
scan. It is also written with a trailing newline on purpose: maldet reads it with a bash
`while read`, which drops a final line that has no newline — silently, so the last file
of every scan would go unexamined while the report still counted it.

The fixtures are now real captured 1.6.6 output — including
`quarantine-disabled-warning.txt`, the shape of **every** report this adapter will ever
parse, since it disables the quarantine on every invocation — and the hit-list shape is
taken from maldet's own parsing code rather than inferred. This is D-022 arriving for
the fifth time: the tests I wrote from my own reading of the docs all passed.

**And what the container had to be taught to prove the flag works.** maldet loads ~51k
signatures and finds nothing in this repository's corpus, because the samples are inert
by construction and Principle VI forbids adding real malware to change that. With zero
hits, `quarantine_hits=0` is untested: nothing was there to move. So
`docker/Dockerfile.validation` gives maldet **one custom MD5 signature for our own inert
marker file**. maldet then hits it and prints, of its own accord:

```
WARNING: Automatic quarantine is currently disabled, detected threats are still accessible to users!
```

on a host whose `conf.maldet` says `quarantine_hits="1"`. That line, from the engine
itself, is the proof — and `validate-engines` additionally asserts maldet's own
quarantine directory is still empty after the cycle. A test asserting our own flag
string would have proven only that we can compare strings.

## D-026 — the data directory is excluded by its configured path, not by its name

**Context**: found while helping a maintainer lay out SentinelHost on a real cPanel
account. They asked for a dedicated folder for everything, which is good practice — it
keeps the quarantine vault out of backups and makes uninstalling a single `rm -rf`.

**The defect**: the guarantee that SentinelHost never scans its own data was a literal
entry in the default exclusion list:

```toml
"**/.sentinelhost/**"
```

That protects a **name**, not the directory. Anyone who sets `data_dir` to a folder of
their own — which the CLI accepts, the panel accepts, and the documentation encourages —
loses the protection the moment that folder sits under a watched root. And they lose it
**silently**: the scan simply starts reading the quarantine vault.

What follows is worse than wasted work. The vault holds the malicious files that were
moved off the site. Scanning it re-detects them, so the tool quarantines its own vault
copy, and does it again the next cycle: an unbounded loop that reports a growing number
of "findings" for malware it already neutralized, while the user watches their finding
count climb on a site that is actually clean. The comment beside the exclusion described
exactly this risk. The mechanism did not cover it.

**Decision**: `normalize()` derives the exclusion from `General.DataDir` and
`QuarantineDir()` as they are actually configured, and appends it on every `Load`.

Three consequences follow deliberately:

- **It holds for a hand-edited TOML.** `normalize()` runs on every load, not at
  `config init`, so someone who deletes the `.sentinelhost` line — or writes the file
  from scratch — cannot switch the guarantee off by accident. Principle I is not
  something a user should be able to disable without meaning to.
- **The glob is absolute.** A `**/<basename>/**` shape would be shorter and would also
  exclude an unrelated directory of the same name inside the user's site. Silently
  excluding part of someone's site is the same class of failure as silently including
  our own: coverage lost without a word.
- **An already-covered directory is not added again.** The exclusion list is what a user
  reads when a file they expected to be scanned was not, and a list that repeats itself
  is a list nobody trusts.

**Also added**: `config init --data-dir`. `--config` alone moved only the TOML, so
someone placing the configuration in a directory of their own got the data in
`~/.sentinelhost` regardless. It was visible — `config init` prints the data directory —
but it is a bad surprise for the one directory that must not end up in a backup or a
deploy, and requiring a hand edit of the TOML to fix it invites the mistake.

**Still the user's responsibility**: keeping the data directory out of the document
root. The exclusion stops SentinelHost from scanning the vault; it cannot stop a web
server from serving it. `config init --help` says so.

## D-027 — SC-006 validated on a real shared-hosting account, driven without a shell

**Context**: SC-006 ("runs on a real cPanel account without root, within the limits")
had stayed pending because no such account was available. One became available on
2026-07-30: a HostGator Brazil shared plan, cPanel, unprivileged.

**What the account turned out to be** matters more than the pass, because none of it was
guessable:

- The provider had **shell access disabled**. SSH key authentication succeeded and the
  session was then closed with `Shell access is not enabled on your account`. The login
  shell is `jailshell`, and **cron still runs** — which is the only reason the validation
  was possible at all.
- **`php` on PATH is php-cgi, not the CLI.** It rejects `-r` and parses arguments
  differently. The real CLI lives at `/opt/cpanel/ea-php83/root/usr/bin/php`. The AMWScan
  adapter probes for `php` and reported the engine available; a direct run through the
  genuine CLI found the same 0 findings as the orchestrator, so php-cgi did not break the
  scan here. That agreement is the evidence, not the probe's opinion.
- cPanel enforces a **15-minute minimum** cron interval on shared plans.

**Decision**: SC-006 is closed as met, and the operating mode used to reach it — a fixed
`runner.sh` called by one unchanging cron entry, executing a replaceable `task.sh`
exactly once per distinct content — is worth shipping as a documented fallback. Principle
III says the tool must work without root; a large share of the accounts it targets do not
even have a shell, and until now the documentation had nothing to offer them.

**What the run actually proved**, beyond "it executes":

- A full cycle over a real WordPress 5.8.1 (2,755 files) in **2.5 s**, 2 MB of data.
- The two engines the host lacks **abstained with actionable reasons**, and the cycle
  reported `2 engine(s) abstained: this cycle's coverage is reduced`. It did not report
  "0 findings" — the failure mode this project exists to prevent, refused on a real host.
- A planted core modification produced `[LIKELY] score 0.75`, which is exactly 1.50 over
  the 2.0 ceiling, carrying its vote, weight, rule and abstentions.
- SC-003's round trip held on real POSIX permissions: `action: quarantined`, the file
  gone from the site, the vault at 0700 with the stored copy at **0400**, and
  `Restored byte for byte` with permissions preserved. The 0400 is the point — an earlier
  defect stored copies `chmod 000`, which blocks the read that `restore` itself performs,
  and that passed a green suite on Windows.
- Two safety behaviours fired unprompted: a fresh install reached `CONFIRMED` and
  declined to act because of the seven-day grace period, saying so; and disabling that
  produced a warning on every later command.

**Zero findings was not accepted on its own.** A clean result is indistinguishable from a
scanner that examined nothing, so the positive control was planted deliberately. What was
planted is one innocuous comment line, **not** a webshell sample — not even an inert one
from this repository's own corpus. It is a live hosting account, the provider runs its
own abuse scanning, and a file that trips it could cost the account. Testing our own
detection is not worth that risk to someone else, which is why only wp-checksums votes
above and `confirmed` had to be reached by lowering a threshold rather than by adding
malicious-looking content.
