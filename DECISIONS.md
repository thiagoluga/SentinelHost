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

## D-028 — votes are merged per content; verdicts are emitted per path

**Context**: found on the real HostGator account while validating detection by path.
Three identical files were planted in three WordPress directories. `wp-checksums`
reported **three findings**. The cycle produced **one verdict**:

```text
✓ wp-checksums         3 finding(s) in 1.19s
VERDICTS
  [LIKELY] score 0.75 — …/wp-admin/includes/update-core-helper.php
SUMMARY  confirmed=0  likely=1  suspicious=0  clean=0
```

**The defect**: findings were grouped by `sha256` alone, and the group was also the unit
of output. Identical content at several paths collapsed into one verdict naming one
path, chosen by "most recently detected". The other two copies appeared in no verdict,
in no summary bucket, and in no skipped counter. They were not reported as anything.

The consequence is this project's defining failure mode arriving at the worst possible
moment. Only the named copy would ever be quarantined; the rest stay on the site while
the cycle reports it as handled. And it is not a corner case: dropping the same webshell
into many directories is standard practice, done precisely so that cleaning one copy
accomplishes nothing. A scanner that helps an attacker there is worse than no scanner.

**Decision**: keep grouping by content, because that is what the grouping is *for* — the
same file flagged by N engines is N votes on one target, not N targets, and splitting
those votes would turn one `confirmed` file into several weak verdicts. Emit one verdict
**per distinct path** within the group, each carrying the **full vote set** for that
content.

The consequences are deliberate:

- A copy is never less actionable than whichever one happened to be named first. Two
  identical files are equally proven, so they reach the same level and both get acted on.
- `VerdictID` now derives from `(scan, sha, path)`. With the old `(scan, sha)` the new
  verdicts would share a primary key, and the store would keep one and lose the rest —
  the same silent loss moved one layer down.
- `distinctPaths` sorts, so the verdict list does not reorder itself between cycles. A
  list that reorders cannot be diffed, and diffing two cycles is how a user answers "is
  this getting better?".

**A test was asserting the defect.** `TestDeduplicationByHashJoinsEnginesIntoOneVerdict`
read: *"The same file seen through different paths (a link, a copy) is still a single
target: the key is the hash."* That is true of a hardlink and false of a copy, and the
tool has to act on both paths either way. It was rewritten rather than deleted, with the
reason recorded — this is D-022 again in a new place: an assumption, plus a test written
from the same assumption, both passing until reality disagreed.

**How it was found matters.** No unit test in this repository plants the same content
twice, because whoever wrote them — me — did not think of it. A real account did, in the
first ten minutes of trying to test detection by path.

## D-029 — `SkippedReasonCounts` holds gaps only, never successes

**Context**: every cycle on the real cPanel account printed the same line, against a
WordPress whose single plugin had just been checked against the official API and found
intact:

```text
✓ wp-checksums         0 finding(s) in 1.149s
    skipped: plugin_verified=1
```

**The defect**: `plugin_verified` counted plugins that **were** verified, and it was
being written into `Scope.SkippedReasonCounts` — the map the CLI and the panel render
under `skipped:`. A success was being reported as a gap.

It is wrong in both directions, and the second is the serious one:

- A user reading `skipped: plugin_verified=1` concludes coverage was lost, and goes
  looking for a problem that does not exist.
- `plugin_without_checksum` — a **real** gap, a plugin nobody could verify — sits in the
  same list, indistinguishable at a glance from a success. Diluting the skip list is how
  a genuine gap stops being noticed, and this project's whole discipline is that anything
  skipped is counted and reported so it *is* noticed.

**Decision**: `SkippedReasonCounts` answers exactly one question — what did the scan NOT
look at? — and only genuine gaps go in it. The `plugin_verified` entry is removed.

No coverage information is lost with it: the verified plugin's files are already counted
in `Scope.FilesConsidered` and `Scope.FilesScanned`, which is where "what was examined"
belongs. The counter was redundant as well as mislabelled.

**How it was found**: by reading output from a real account rather than a fixture. The
line had appeared in every cycle of this session and I had walked past it repeatedly
before asking what it actually meant. A counter that no test asserted, printing a
reassuring-sounding word in the one place reserved for bad news.

## D-030 — a documented operating mode for accounts with no shell

**Context**: validating SC-006 on a real HostGator account ran into a wall that the
documentation had no answer for. SSH key authentication succeeded, and the server then
closed the session:

```text
Shell access is not enabled on your account!
```

That is a provider setting. It cannot be changed from the account, asking support may
take days or be refused, and the quickstart assumed a shell throughout.

**Decision**: ship the mechanism that got past it, as `contrib/cpanel-no-shell/`. One
unchanging cron entry calls a fixed `runner.sh`, which executes a replaceable `task.sh`
**exactly once per distinct content** — fingerprinting the file, remembering what it last
ran, exiting silently when nothing changed. The cron entry never needs editing; the
operator replaces one file.

Principle III says the tool must work without root. A large share of the accounts this
project exists for do not even have a shell, and until now they had nothing.

**Three properties are load-bearing**, and are commented as such in the script:

- **The fingerprint is written BEFORE the task runs.** A task that trips a resource limit
  or wedges the account must not run again on the next tick and do it again. A task that
  failed has still been attempted; repeating it automatically turns one bad command into
  a loop.
- **The exit code is always recorded, even when the task printed nothing.** Silence is
  not evidence of success — the same rule that makes an engine abstain rather than report
  zero findings.
- **A lock, and a log ceiling.** Two ticks must not run concurrently against one SQLite
  database and one quarantine vault, and a runaway log on a disk-quota-limited account is
  its own small outage.

**The security tradeoff is stated first in the README, not buried.** A file that cron
executes and that the operator can replace over FTP is an arbitrary-code-execution
channel on the account — precisely the shape of the backdoors this project exists to
find. It is worth having while in use and not otherwise, it must live outside the
document root, and the cron entry should be removed when the work is done. Documenting a
technique without documenting what it costs would be the wrong kind of helpful.

**Not solved by this**: the web panel listens on `127.0.0.1` and needs an SSH tunnel, so
it stays out of reach until the provider enables shell access. Everything the CLI does
works through this.

## D-031 — a cycle where no engine voted is `partial`, and exits non-zero

**Context**: found by reading the `--json` output of a cycle in which all four engines
abstained. The human-readable report said the right thing. Nothing else did:

```json
{ "status": "completed", "engines_ran": null, "verdicts": {}, "files_scanned": 1 }
```

Exit code 0. Status `completed`. No verdicts.

**The defect**: to the panel, to a webhook consumer, or to any monitoring check asking
`status == "completed" && no verdicts`, that is indistinguishable from *"scanned
everything, the site is clean"*. It is this project's defining failure mode reaching the
machine-readable interface — the one place where nobody is reading a sentence about
reduced coverage.

`ScanStatus.CountsAsVote()` already enforces the rule one level down: an engine that
could not run abstains rather than reporting zero findings. The cycle had no equivalent.

**Decision**: `Summary.AnyEngineVoted()` is the cycle-level counterpart. When it is
false:

- the cycle's status is `partial`, never `completed`;
- `scan` exits **2**, not 0;
- the report says `NOTHING WAS SCANNED: all N engine(s) abstained` followed by *"An empty
  result below says nothing about this site"*, rather than the same "coverage is reduced"
  sentence it printed whether one engine abstained or all of them did.

Three details are deliberate:

- **Some abstentions still count as `completed`.** A cycle with one working engine really
  did scan, and its result is incomplete rather than absent. Marking every such cycle
  partial would make `partial` the permanent normal state of any host without yara and
  maldet — which is most of them — and a status that is always on carries no information.
- **`exitError` (2) rather than a new code.** This *is* a failure: the tool was asked to
  scan and did not. A fourth exit code would leave every existing integration treating
  the new value as success by default.
- **Availability alone is not participation.** The check reads `Available &&
  Status.CountsAsVote()`, so an engine that started and then failed, timed out or was
  killed does not rescue the cycle. That is the case that matters most, and testing only
  `Available` would have reintroduced the bug for it.

**How it was found**: by looking at the JSON at all. The text output had been correct
this whole session and I had read it a dozen times; the machine interface next to it was
saying the opposite thing, and nothing checked that the two agreed.

## D-032 — the panel says when nothing was scanned, and stops showing zeros as facts

**Context**: the counterpart of D-031, found immediately after it by asking whether the
web panel repeated the mistake the CLI had just stopped making. It did.

With every engine unavailable the dashboard showed four KPIs reading zero and one banner:

> 4 of 4 engines are unavailable. This site's coverage is reduced — see the Engines tab.

The same sentence it prints when one engine of four is missing. Nothing on the screen
distinguished "we looked and found nothing" from "we could not look at all", and the
zeros were rendered exactly as they are on a genuinely clean site.

That matters more here than in the CLI. The panel exists for the person who is **not**
going to read a log or check an exit code — FR-014 and SC-004 are about someone
non-technical deciding what to do — and it was the surface most likely to be believed.

**Decision**: when `engines.available` is 0 the banner becomes an error-styled
`Nothing was scanned.`, saying in the same breath that the counts below say nothing
about this site, and pointing at the Engines tab, where each engine already explains what
it needs. The `confirmed`, `likely` and `suspicious` numbers are dimmed and struck
through, with a title attribute reading *"Not measured: no engine was able to run in the
last cycle"*.

**Struck through rather than hidden or blanked.** A missing number invites the reader to
assume the page is broken; a dash invites them to reload. A struck-through zero says
the measurement was attempted and did not happen, which is the true statement.

**Partial coverage keeps its existing, milder banner**, for the same reason D-031 keeps
`completed` for a cycle with one working engine: on most shared hosts two of four engines
are permanently unavailable, and a warning that is always at full volume is one nobody
reads.

Verified in a browser against the running panel, driving the real `loadStatus()` with a
synthesized `/api/status` response for all three cases — no engines, some engines, all
engines.

## D-033 — the login lock-out is counted in the store, not in process memory

**Context**: found while writing a CGI mode for the panel. The comment I had just written
claimed the brute-force counter lived in the store. It did not — `rateLimiter` was a
`map[string][]time.Time` held in the process.

Under `serve` that is fine: one process sees every request. It stops being fine the
moment the panel is served any other way — CGI, FastCGI, one process per request. There
the map arrives **empty on every attempt**, so the lock-out does not exist at all, while
every page looks and behaves exactly as before and nothing in the logs says the
protection was switched off.

That is worse than having no such mode: the panel's single password would be the only
barrier on a publicly reachable endpoint, with unlimited attempts against it.

**Decision**: the counter moves into the same SQLite the sessions already use.
`Store.RecentLoginAttempts` / `RecordLoginAttempt` / `ClearLoginAttempts`, one small
query per login.

Four details are deliberate:

- **A store error ALLOWS the attempt.** A database hiccup must not lock the legitimate
  owner out of their own panel. The opposite default turns a transient error into a
  denial of service against the one person entitled to log in, and the failure is loud
  elsewhere.
- **An empty window deletes the row** instead of writing one. Without that, every IP that
  ever tried once leaves a row forever and the settings table grows with the internet
  rather than with the account.
- **Housekeeping prunes counters older than an hour.** The window is one minute, so
  anything older cannot influence a decision. That covers the IP that never comes back,
  which the delete-when-empty rule alone does not.
- **A refused attempt still rewrites the window**, so it keeps sliding and one old burst
  cannot pin an IP out indefinitely.

**This was written before the mode that needed it**, and shipped on its own. The CGI mode
turned out not to be viable on the host that motivated it — Apache there refuses to
execute user CGI — but the defect is real in any per-request deployment, and it was true
before anyone tried one.

**How it was found**: by checking a claim I had just made in a comment. Thirty seconds in
`auth.go` against a sentence I had written as fact. That is the fifteenth instance of
D-022 in this session and the only one where I was the sole reviewer.

## D-034 — the panel reaches shared hosting through PHP, not through a daemon

**Context**: on the validation account, `sentinelhost serve` survived **fourteen
minutes** before the host killed it, and the shell was disabled so an SSH tunnel was out
too. Two other routes were tested and both refused: Apache would not execute user CGI,
and an arbitrary public port is firewalled off.

What was available is what shared hosting has always had. Measured on the account:

```text
PHP-RAN 8.3.32 sapi=litespeed
disable_functions: (none)
exec/fsockopen/curl_init: available
loopback socket: OPEN
panel through PHP: REACHED IT
```

**Decision**: `contrib/php-bridge/` — a PHP file in the document root that checks whether
the panel is answering on the loopback, starts it if it is not, and proxies the request.

The insight it rests on is worth stating, because it took a while to see: **WordPress
does not stay running either.** It is not more robust than a Go daemon; it simply never
holds a process. The web server is what stays up, and the web server belongs to the host.
The bridge gives the panel that same shape, and the fourteen-minute lifetime stops being
a problem to fight — the next visit fixes it.

Four things in it are load-bearing:

- **A non-blocking lock around the start.** Two simultaneous requests would otherwise
  both find the panel down and both start one: two processes against one SQLite database
  and one quarantine vault. Non-blocking on purpose, so a request that loses the race
  waits for the panel rather than holding a PHP worker open waiting for a lock.
- **The panel is re-checked after the lock is taken**, because the other request may have
  finished starting it in between.
- **`X-Forwarded-Proto` is set from what actually happened**, never assumed. The panel
  marks its session cookie `Secure` from that header, and guessing "https" would hand out
  a cookie that travels in the clear.
- **The binary and the data stay outside the document root.** A Go binary served as a
  download is a gift to anyone probing, and the vault holds the very files removed from
  the site — reachable over the web, an attacker fetches their own webshell back.

**This deliberately puts an administrative panel on a public URL.** The shipped
`.htaccess` carries an IP restriction, commented out with the reason next to it: the
password is real protection (argon2id, sessions, and a rate limiter that now survives
across processes — D-033), and it should still not be the only layer.

**Not validated on the host yet.** The bridge is written and staged there; the account's
cron stopped firing before the installation task ran. Nothing here is claimed as proven
beyond what the probe above measured — which is that every capability it needs exists.
## D-035 — the panel addresses itself relatively, so it works anywhere it is mounted

**Context**: found the moment a reverse proxy in front of the panel worked. The panel
came up, served its page, and then:

```text
api/session      -> HTTP 200
assets/app.js    -> HTTP 404
assets/app.css   -> HTTP 404
```

The HTML arrived and rendered as bare markup.

**The defect**: the panel addressed itself from the domain root — `<link href="/app.css">`,
`fetch('/api/status')`. That works only when the panel **is** the site. Mounted at
`/sentinel/`, the browser asks the SITE for `/app.css`, gets the site's 404, and the panel
loads unstyled and inert with nothing on screen explaining why.

It was never noticed because every previous test served the panel at the root of
`127.0.0.1:8787`. The assumption was invisible until something mounted it elsewhere — and
mounting it elsewhere is the only way it is reachable on shared hosting at all.

**Decision**: the panel derives its mount point from the page it was served as:

```js
const BASE = new URL('.', document.baseURI).pathname;
```

and every request goes through a `url()` helper. `document.baseURI` already carries the
directory the document came from, so this is correct at the root as well — nothing is
configured, and nothing has to be told where it was installed.

**Three tests hold it**, and they read the shipped assets rather than a copy: no `href`
or `src` starting at the root, every `fetch` going through the helper, and the base being
derived from `document.baseURI` rather than assumed. A regression here is silent by
nature — the page still loads — so it needs a test that fails loudly.

**How it was found**: by looking at what the browser would actually receive, on a real
host, instead of at whether the request reached the panel. The API answered 200 and the
page arrived; by every check written before this one, it worked.

## D-036 — the `hidden` attribute is enforced globally, not per component

**Context**: reported by the maintainer opening the panel on their own site for the first
time. The first-access screen appeared — *"Set the panel password"* — with a dialog on
top of it reading **Confirm / type: purge**. Neither Cancel nor Confirm did anything.

**The defect**, in one line of CSS:

```css
.modal{position:fixed;inset:0;…;display:grid;…}
```

The `hidden` attribute applies `display:none` through the **browser's own** stylesheet,
which any author rule outranks. So the purge confirmation — the dialog for the only
irreversible operation in this project — was permanently on screen, over everything.

And it could not be dismissed. The Cancel and Confirm handlers are attached when the
dialog is opened deliberately by `confirmPurge()`; this one never was, so the buttons did
nothing. A first-time user was blocked at the password form by a dialog asking them to
type "purge".

**Decision**: `[hidden] { display: none !important; }`, declared before the component
styles.

Not a `.modal[hidden]` rule. Every element the panel toggles with the attribute — the
gate, the app, both banners — is exposed to exactly this the moment it gains a display of
its own, and fixing the one instance leaves the next to be found the same way: by
somebody opening the panel and being confronted with it. `!important` is warranted here
in a way it rarely is: nothing should ever out-specify "this element is not here".

**Two tests hold it**: the rule exists with `!important`, and it appears before `.modal`.
The second one matched the rule quoted inside its own explanatory comment on the first
attempt and failed for that reason — line-anchored now, and worth recording as the sort
of thing a string-matching test does.

**How it was found**: by a person opening the page. Every automated check passed, the
panel returned HTTP 200, the assets loaded, and the API answered — nothing anywhere
looked at what was actually on the screen.

## D-037 — the bridge logs where each request spent its time, and stops hanging

**Context**: the panel stopped answering entirely — no error page, no response at all, a
browser waiting 300 seconds — while the site around it stayed fine. I said the likeliest
reading was panel processes piling up against the account's limit. It was not:

```text
panel processes: 1     (alive 15m57s, 13.5 MB)
processes on the account: 6     (limit 300)
starts, whole session: 7
errors: none
```

The panel was up and healthy. The guess was wrong, and there was nothing recorded
anywhere to have checked it against.

**Decision**: the bridge writes one line per request with where the time went.

A proxy that can hang has exactly three places to hang in — the liveness probe, the cold
start, and the upstream call — so all three are timed:

```text
200 GET    /            probe=0.00s start=0.15s upstream=0.00s (cold start)
200 GET    /app.css     probe=0.00s start=0.00s upstream=0.00s
```

**And the upstream timeout drops from 60s to 20s.** A proxy that hangs is worse than one
that fails: the browser learned nothing from those 300 seconds, and every pending request
held a PHP worker open the whole time. Twenty seconds is generous for a panel on the
loopback, where the slowest page measured is under a second, and anything past it is a
fault worth reporting as one.

**What the instrumentation then showed**, on the case nothing had tested — four requests
arriving at once with the panel down, which is what opening a page actually does, and not
what sequential `curl` does:

```text
200 0.167s /api/session
200 0.167s /app.css
200 0.167s /app.js
200 0.170s /
panel processes: 1
```

Four cold starts of 0.15s each, one process. The lock works.

**The original hang remains unexplained**, and that is recorded rather than covered over.
What exists now is a log that will say what happened next time, and a ceiling that turns
a hang into a 502 with a timing line instead of a browser spinning for five minutes.

**The lesson is the guess.** I offered a cause with confidence, from a log that showed
repeated start lines and nothing else, and the numbers contradicted it fifteen minutes
later. The reason it took fifteen minutes is that nothing was measuring — which is the
same failure this project keeps finding in itself, one layer out.

## D-038 — reachability changes the action, never the verdict

**Context**: the maintainer noticed that findings from the validation run were all inside
`/home1/motel510/.trash/wordpress` — the account's deleted-files area — and asked for the
tool to at least know that.

The useful question turned out to be broader than the trash: **can a visitor fetch this
file right now?** A webshell in the document root can be executed by anyone with the URL,
this minute. The same webshell in the trash cannot be executed by anybody. A backup
directory, a path above the site, and the trash are all the same answer.

**Decision**: `internal/reach` classifies every path as `web_reachable`, `trash`,
`outside_docroot` or `unknown`. The result is recorded on the finding and the verdict,
and it feeds the ACTION — the same place the whitelist acts (D-006).

**What was deliberately NOT done**: adjust the score. Tempting, and it is the mechanism
through which real findings quietly stop being seen. D-003 keeps the consensus showing
its votes rather than a number somebody tuned by context, and a file in the trash is
exactly as detected as it was before; only the automatic quarantine is withheld, with
`skipped_not_reachable` and a reason.

Nor was the trash excluded from the scan. An attacker who learned that would keep their
payload there, and silent exclusion is what this project exists to prevent.

Five decisions inside it are load-bearing:

- **`unknown` counts as reachable.** When the question was never answerable — no document
  roots configured — the safe reading is the urgent one. The opposite default would
  downgrade every finding on every installation that never set them.
- **Trash is matched as a whole path SEGMENT, never a substring.** `public_html/trash/`
  full of a user's drafts, `contrash/`, `mytrash/` — none of those are a control panel's
  bin, and downgrading a served file because of a folder name would hide a live finding.
  This is D-026 applied before it could bite a second time: names are a hint, paths are
  the answer.
- **`under()` compares segments, not prefixes.** `/home/u/public_html2` is not inside
  `/home/u/public_html`; a prefix test puts somebody else's site under this one's root.
- **Trash is checked before the document roots.** A panel's bin can sit inside a served
  directory, and "the web serves this" is the wrong headline for a file the account has
  already deleted.
- **The location is recorded even when it is reachable.** "This IS served" is the half of
  the answer that makes a finding urgent; a field that appeared only for the sheltered
  cases would read as a badge for harmless results.

**And unreachable is not safe.** Every explanation says so: the cPanel trash restores with
one click, and restoring the site restores whatever is in it. Leaving that out would
manufacture exactly the confidence this project is built to refuse — the maintainer's
account has three whole WordPress installations sitting in there.

## D-039 — the config API sends the names the TOML uses, not Go's field names

**Context**: reported from a screenshot of the running panel. Everything looked right —
the dashboard, the KPIs, the coverage per engine — with one toast in the corner:

```text
Could not load the configuration: Cannot read properties of undefined (reading 'enabled')
```

**The defect**: the config structs carried only `toml:` tags. Go therefore serialized them
with its own field names:

```json
"alerts": { "Email": { "Enabled": false, "Host": "", … } }
```

while the panel reads `CFG.alerts.email.enabled`. The top-level keys were right, because
the handler builds that map by hand; every field inside them was not.

**What makes this worth a decision rather than a one-line fix** is how it failed. The
whole Settings tab was being populated from `undefined`, and assigning `undefined` to an
input's `.value` throws nothing — it just leaves the field blank. A user would have seen
an empty form, edited it, and saved defaults over their own configuration. The single
toast came from the one line that read a property *of* the undefined object, and that
accident is the only reason anybody found out.

**Decision**: every `toml:` tag has a `json:` twin with the same name. The panel and the
file a user edits by hand now name the same setting the same way, and the API contract
stops depending on Go identifiers — a rename in Go would otherwise silently break the
panel.

**The test compares the two sides.** It extracts every `CFG.<section>.<field>` the panel
reads out of `app.js`, marshals the real config through the same path the handler uses,
and reports any the API does not send. A test asserting the Go structs would have passed.
A test asserting the JS would have passed. Only reading both and comparing them catches
this, which is the same shape as the fixture-versus-reality rule in D-022 — one side
verified against the other, rather than each against my idea of it.

Verified by reverting the fix: the tests fail, and with it restored they pass.

**How it was found**: by a person looking at a screen, again. This is the second defect in
two days that every automated check passed — HTTP 200, assets loaded, API answering — and
that was visible immediately to somebody with the page open.

## D-040 — the scope is the account, and the document roots are discovered

**Context**: the maintainer corrected the scope. A hosting account is rarely one site —
addon domains, subdomains and parked domains each get their own directory — and a webshell
in a secondary domain is exactly as executable as one in the primary. Watching a single
document root leaves the rest invisible.

**Decision**: `reach.DiscoverDocumentRoots` reads the roots instead of asking for them, and
the account's own directories are excluded by default so scanning the whole home is
practical.

**Why discovery rather than configuration.** A hand-written list is right on the day it is
written and wrong the first time a domain is added — and nothing says so, because a
MISSING root only ever makes findings look LESS urgent than they are. That is the one
direction this project cannot afford to be wrong in.

Two sources, in order of trust. cPanel's `~/.cpanel/userdata/<domain>` files carry a
`documentroot:` line, which is the server's own answer. Failing that, directories that
behave like a site — an `index.php` or `index.html` within three levels of the home.

**And the second source is the one that works.** On the validation account,
`.cpanel/userdata` is not readable by the user at all: the primary source returned
nothing. The fallback found both real sites and two false positives under `tmp/`, which
the internal-directory list already excludes. What I wrote as the weak option carries the
whole feature on the only host it has been tried against.

**The exclusions are measured, not guessed.** From that account:

| | files | PHP | size |
|---|---|---|---|
| whole account | 32,416 | 11,399 | 5.5 GB |
| `.trash` | 16,698 | **11,140** | 759 MB |
| `mail` | 9,206 | 98 | **2.4 GB** |
| `tmp` | 5,655 | 150 | 338 MB |
| `public_html` | 78 | 3 | 5.0 MB |

`mail`, `tmp`, `logs`, `etc`, `ssl` and the panel's own directories are excluded: none is
served by the web, none executes, and the 98 "PHP files" under `mail/` are e-mail
attachments — spam samples in a maildir, producing findings nobody can act on about files
that are not on the site.

They are **exclusions, not silence**: each is counted and reported under `excluded`, and
removing a line brings it back. A scanner that quietly skips two thirds of an account and
says "0 findings" is precisely what this project exists to prevent.

**The trash is deliberately NOT excluded.** It holds 11,140 of the 11,399 PHP files on
that account. Hiding it would remove almost everything scannable and reward anyone who
worked that out. It is scanned, classified as `trash`, and left alone by the automatic
action instead (D-038).

**A name is not a directory** — and I made the mistake anyway, in the same commit that
says so.

The exclusions shipped as `**/mail/**`, `**/tmp/**` and friends, which match a directory
of that NAME at any depth. CI caught it on Linux within minutes: `**/tmp/**` excluded
`/tmp`, where the suite builds its fixtures, so the 20,000-file benchmark scanned **zero
files** and reported success at the level below. On a real site it would have excluded
`public_html/app/tmp/`, which is a stock directory in Laravel and CakePHP — live content,
silently skipped.

They are now anchored to the account's HOME and nowhere else: `~/mail`, `~/tmp`. That is
what was meant all along, and it is the same correction as D-026 (data dir by path, not by
name) and D-038 (trash by segment, not by substring). Third time it was written down,
first time it was actually committed.

The tests now include `public_html/app/tmp/cache.php`, `public_html/mail/contact.php` and
`/tmp/fixture/x.php` — the cases that broke — alongside `public_html/mailings/` and
`public_html/tmpl/`, which were the ones I thought of. Verified on Linux in the validation
container, not only on the workstation: this failure was invisible on Windows, where the
suite's fixtures do not live under `/tmp`.

## D-041 — findings are grouped by where the file sits, and the quiet groups start closed

**Context**: the first whole-account scan produced **209 findings**, nearly all of them
framework code — Laravel, Symfony, psysh — inside WordPress installations sitting in the
trash. On the live site there were a handful. An undifferentiated list buries the ones
somebody can act on under the ones nobody can.

**What was NOT done**: lower their score. They are `suspicious` at 0.32, which is one
heuristic engine voting alone and is exactly right — the consensus is behaving as designed
and D-003 keeps it showing its votes rather than a number tuned by context. The problem is
not the verdicts, it is the reading order.

**Decision**: one section per location, ordered by urgency — served by the web, unknown,
unrecorded, outside the document root, trash. The first three open, the last two closed.

**Closed is not hidden**, and that distinction is the whole design. The summary carries
the count, the reason the group exists, and **the worst level inside it**, so a
`confirmed` finding in a closed group announces itself without being opened. It is the
same rule the scan report follows for skipped files: anything out of sight stays counted
and explained. A group that hid its count would be a filter pretending to be a grouping.

**The collapsing is an explicit rule, not the browser's default.** `<details>` is supposed
to hide its contents through the user agent stylesheet — the weakest link in the cascade.
Measured in a real browser, the cards stayed laid out at full height with the element
closed, and a bare `<details>` did too, so it was not our styling. Rather than keep
bisecting somebody else's cascade:

```css
.loc-group:not([open]) > *:not(summary) { display: none !important; }
```

That is the second time this project has been bitten by relying on a default any other
rule can outrank — the first was the purge dialog that would not close (D-036). When
something must not be on screen, say so.

**Verified in a browser**, with the group closed and open, because the last three defects
in the panel all passed every automated check and were visible immediately to somebody
looking at the page.

## D-042 — the panel fetches the tab you are looking at

**Context**: the panel intermittently would not open on the validation account — the page
loaded and nothing appeared — and the site itself returned 503 for a few seconds at a
time before recovering.

The bridge's request log (D-037) answered the first half immediately: every request
returned 200 in 0.00s. The server was serving fine.

It also showed the shape of one page view:

```text
/  /app.css  /app.js  /api/session  /api/status  /api/engines
/api/verdicts  /api/quarantine  /api/engines  /api/config  /api/cron-line
```

Eight API calls for one visible tab, with `/api/engines` requested **twice** — once for
the dashboard summary and once for its own tab.

**What is NOT established**: that this caused the 503s. They hit the site's root, a static
page, which points at account-wide throttling that anything could trigger. Three earlier
hypotheses about this account were wrong, and this one is not being added to the list as
though it were proven.

**What is indefensible regardless**: on shared hosting every one of those requests is a
PHP process holding a worker while it proxies, and the account has a hard ceiling on how
many may run at once. Fetching five invisible tabs to show one is exactly the waste
Principle IV exists to prevent — the tool is a guest on somebody's hosting.

**Decision**: a loader table per tab, fetched when the tab is first opened. The duplicate
`/api/engines` is gone. A page view is now two calls instead of eight.

Three details:

- **Sequential, not concurrent.** Four requests at once from one page view is what a
  constrained account notices, and nothing here is worth racing for.
- **A failed load un-marks the tab**, so re-opening it retries instead of showing a blank
  pane forever.
- **An action invalidates everything and re-fetches only what is on screen.**
  Quarantining a file changes the findings, the quarantine and the dashboard counts, so
  none can be trusted afterwards — but fetching all of them to show one is the waste being
  removed.

## D-043 — the panel shows what the engine actually saw

**Context**: the maintainer asked for a preview of the offending line. Checking what the
engines record rather than assuming turned up that **half of it already existed and was
never displayed**:

| Engine | Evidence recorded | Position |
|---|---|---|
| `amwscan` | the offending snippet | **line number** |
| `php-malware-finder` | the strings that matched | **byte offset** |
| `maldet` | only `{TYPE}signature` | none |
| `wp-checksums` | a message | none |

It was going into `matched_content` and `matched_offset`, into the database, and no
further. The votes told a user that a file was flagged and by whom; they never said why,
and "why" is the difference between somebody who can decide and somebody who has to trust
us — which Principle V exists to prevent.

**Decision**: an expandable block per finding, fetched when it is opened.

- **On demand, not with the list.** A findings page holding two hundred cards would
  otherwise be two hundred extra requests, on an account with a ceiling on how many
  processes may run at once (D-042).
- **The unit is named.** AMWScan counts lines and yara counts bytes; "offset 4211" and
  "line 4211" send someone to very different places in a file.
- **An engine with no snippet says so.** maldet records which signature matched and never
  the text, and an empty box reads as a load that failed.
- **Collapsed explicitly**, for the third time in this panel — the user agent's own hiding
  is the weakest link in the cascade (D-036, D-041).

**The snippet is attacker-chosen text**, and it enters the DOM through `textContent`. A
file named `<img src=x onerror=…>.php` is a legal filename, and rendering it as markup
would turn the panel into an attack on the person reading it. Verified in a browser with a
deliberately hostile snippet carrying an identifiable element: it stayed text.

The test for this checks for `.innerHTML =`, an assignment, rather than the word —
its first version matched the file's own comments explaining why innerHTML is forbidden,
which is the second time a string-matching test has found the explanation instead of the
code.

**Not done, by instruction**: the diff against the official WordPress file for
`wp-checksums` findings. It is the only way to show a line for a hash-based detection, and
it would mean a network call per preview.

## D-044 — the classification reaches the database, and the tool stops reporting itself

**Context**: a screenshot of the panel showing findings on the real account. Two defects
in one picture, and the second is the more embarrassing.

**The location never reached the panel.** Every finding sat under *"Location not
recorded"*, including files plainly inside a discovered document root. The `verdicts`
table had no `file_location` column: the value was computed on every cycle, printed by
the CLI, and dropped on the way to disk.

Nothing failed. The CLI was right, the panel was empty, and the two never compared notes —
which is why the test now writes a verdict and reads it back rather than checking either
side alone. Existing rows keep `''`: they were decided before the classification existed,
and inventing a location for them would assert something nobody measured. The panel has a
group that says exactly that.

**And the flagged file was our own PHP bridge.** `sentinel/index.php`, at `suspicious`,
rule `Function`, because it calls `exec()` — which is correct detection. Starting the
panel is the bridge's entire job.

The bridge has to live IN the document root; that is what makes the panel reachable on
hosting with no shell. So the data-directory exclusion never covered it, and every install
using the bridge would carry a permanent finding about a file this project put there. A
scanner that spends its credibility reporting itself teaches the user to ignore it.

**Decision**: a component marker. The bridge ships `.sentinelhost-component` beside
itself, and any directory carrying it is left out of the scan.

**By the marker, never by the name.** A directory called `sentinel` proves nothing —
anybody can choose that name, including somebody who read this code and wants to know
where to put a payload. Presence of a file we install is a claim only we can make about
our own installation. This is the fourth time in this project that a name has been
mistaken for a path (D-026, D-038, D-040), and the first time the alternative was designed
in from the start rather than after CI caught it.

**Deleting the marker puts the bridge back in scope**, and the file says so. Wanting the
scanner to watch code in your own document root is reasonable, not paranoid — the finding
that comes with it is now a choice rather than a surprise.

## D-045 — a flag documented as global has to be global

**Context**: two automated cycles against the real account were spent producing nothing,
and the run that consumed them reported success.

The help text says:

```
GLOBAL OPTIONS
  --config <file>   Path to the TOML
```

The parser read `os.Args[1]`, found `--config`, and answered `unknown command: --config`.
The word *global* is a promise that the option belongs to the program rather than to one
subcommand, and every CLI convention that carries the word allows it before the
subcommand. Ours allowed it only after.

**What it actually cost.** A scan invoked as `sentinelhost --config X scan --full --json`
exited 64 and wrote a zero-byte report. The check reading that report asked
`grep -q 'sentinel/index.php'`, found nothing, and printed *"the bridge is out of
scope"* — a pass, from a file that was empty because the program never ran.

That is the failure this repository exists to prevent, committed by its own verification
step. `ScanStatus.CountsAsVote()` stops an engine that could not run from voting; nothing
was stopping a *check* that could not run from reporting a clean result.

**Decision**: `--config` is accepted before or after the subcommand, and the two forms
produce identical arguments. Fixing the parser rather than the help, because the help
describes what a user would reasonably expect and the parser describes an accident.

`needsValue` is a deliberate short list rather than a heuristic: treating every
unrecognised leading flag as value-taking would let `--json scan` swallow the subcommand.

**And every remote check now proves it ran before it interprets a result.** A byte count
on the report, a `grep -c` rather than a silent `grep -q`, an explicit line when a field
is absent. A count of zero and a command that never executed look identical in a log; only
one of them is information.

## D-046 — the listing is one row per file, not one per cycle

**Context**: a screenshot of the panel showing the same path three times, and then the
database behind it: **1050 verdict rows for 213 distinct files**, growing by ~208 every
cycle.

A verdict's id includes the scan that produced it, deliberately (see `verdictID`): the
record of what was decided when is worth keeping, and `ON CONFLICT(verdict_id)` therefore
never fires across cycles. The consequence nobody had followed through: a cron every
fifteen minutes re-decides the same file **ninety-six times a day**, and the panel listed
every one of them. The page a user opens to decide what to do was mostly the same file,
repeated.

**Decision**: keep the history, collapse the listing. The newest row per
(`file_path`, `file_sha256`) is what the panel shows; `AllCycles` asks for the rest.

Keyed on both columns, not either alone:

- **Not content alone** — the same payload at two paths is two decisions, and quarantining
  one does not clean the other. That is exactly what `verdictID` was fixed to preserve;
  collapsing by hash would have undone it one layer up.
- **Not path alone** — a file whose content changed is a different thing to decide about.
  The old verdict does not describe the new file.

**`ROW_NUMBER`, not `GROUP BY`.** A bare `GROUP BY file_path` with no aggregate leaves
SQLite free to return any row from each group; the `ORDER BY` of an inner query does not
bind it. The obvious spelling would have shown an arbitrary cycle's verdict and looked
right nearly always. `verdict_id` breaks ties, because rows from one cycle share a
`created_at` to the nanosecond — observed in the real data.

**The filter runs before the collapse**, so `pending only` returns the newest row that is
*pending*, rather than taking the newest row and then discarding it for being
acknowledged — which would hide a file still awaiting a decision.

**A fixture was describing one file while the tests meant two.** Every `sampleVerdict`
shared one path and one hash, so by the identity the listing now uses they were the same
file decided twice, and the collapse merged them. The path now carries the id. Worth
recording because the failing test looked at first like the collapse was wrong, and it
was the fixture that had never said what it meant.

## D-047 — timestamps that sort the way the clock does

**Context**: looking for the next defect after D-046, not prompted by a symptom. The
store writes time with `time.RFC3339Nano`, and SQLite compares `TEXT` byte by byte.

`RFC3339Nano`'s own documentation says it *"removes trailing zeros from the seconds
field"*. So the stored fraction is variable-width:

```
2026-08-03T17:01:23Z              is .000000000
2026-08-03T17:01:23.9Z            is .900000000
2026-08-03T17:01:23.905504385Z    is .905504385 — the latest of the three
```

Compared as text, byte four of the fraction is `Z` (0x5A) against `0` (0x30), so **the
earlier instant sorts last**. A whole second is worse: it carries no fraction at all and
sorts after everything within its own second. Confirmed by running it, not by reading the
documentation:

```
chronologically  a < b : true
as SQLite sorts  a < b : false
```

**What rested on this**: `ORDER BY created_at DESC` in every listing,
`LatestVerdictForHash`, the one-row-per-file collapse shipped hours earlier in D-046,
session expiry, quarantine retention, delivery retry scheduling. All of them decide
something by comparing these strings.

It is wrong for roughly one write in ten — whenever the nanosecond value ends in a zero —
and never the same way twice, which is why it had never produced a reproducible complaint.
`ORDER BY` on a database is the last place anyone looks.

**Decision**: a fixed nine-digit layout, `2006-01-02T15:04:05.000000000Z07:00`, so
lexicographic order is chronological order. Reading still accepts the old shape, because
`RFC3339Nano` parses any fraction width and every timestamp already on disk has to keep
meaning what it meant.

**Migration 3 rewrites what is already stored**, across every timestamp column in every
table. New writes being correct is not enough: a table holding both shapes sorts wrongly
at each boundary between them, and that boundary is exactly where "most recent" lives.

Guarded twice — the `LIKE` matches only a well-formed `YYYY-MM-DDThh:mm:ss…Z` so a NULL or
an empty string is left alone rather than mangled into a plausible wrong time, and the
length check skips rows already at nine digits. There is a test for each guard, including
one that runs the migration three times over.

## D-048 — the evidence belongs to the cycle that decided

**Context**: a screenshot of one verdict on `pluggable.php` showing **one** `wp-checksums`
vote and **three identical** `wp-checksums` evidence blocks, all reading
`core file altered: wp-includes/pluggable.php`.

`FindingsForHash` returns every finding recorded for that content hash across every cycle.
A cron running every fifteen minutes re-detects the same file all day, so the panel
collected three cycles' worth and stacked them under one verdict.

The same shape as D-046, one layer down — and D-046 made it visible: collapsing the
listing to one verdict per file left three evidence blocks under it, where before the
repetition was spread across three cards and looked like three findings.

**It is worse than noise: it contradicts the card it sits in.** The votes printed directly
above say one engine voted once. Principle V says every verdict carries its votes so a
user can answer "why was this file quarantined?" — evidence from a cycle other than the
one being displayed answers a different question, and quietly disagrees with the answer
above it.

**Decision**: `FindingsForVerdict(sha, scanID)`. The verdict's votes come from one cycle's
findings; that cycle's findings are what appear under it. `FindingsForHash` stays, because
the full history is still the right answer for anything asking about the file rather than
about one decision.

**A cycle that recorded nothing shows nothing, and says so.** The panel's empty message
now reads *"the cycle that produced this verdict recorded no detail"* rather than *"no
detail was recorded for this file"* — the second sentence is false under the new scoping
and would send someone looking for a bug that is not there. The response also carries an
explicit `findings_count`, so an empty list can be told apart from a request that failed.

## D-048 — the bridge hands the waiting back to the client

**Context**: the panel returned the web server's own *Service Unavailable* page — the one
that adds *"a 503 was encountered while trying to use an ErrorDocument"*. That sentence is
the diagnosis: **PHP never ran**. The bridge's own 503, with its explanation and
`Retry-After`, never had the chance to be produced.

I first read the static site root answering `200` in 0.14s as proof the account was
healthy, and said so. It proves nothing of the kind — a static file needs no PHP worker.
The 503 was specific to PHP, and the root was answering *because* it never asked for one.

**The mechanism.** A cPanel account has a small ceiling on concurrent PHP processes. The
panel is a long-running daemon that shared hosting reaps whenever it goes idle, so a cold
start is routine rather than exceptional, and one page view fires more than one request.
Every request arriving while the panel was down sat on a worker for up to **8 seconds**
(`$bootWait`). A handful at once exhausts the pool, and from then on the *server* refuses
requests before PHP is reached. The panel was starting normally the whole time.

**Decision**: wait only long enough to cover a panel that answers almost immediately —
`$bootWait` drops from 8.0s to 1.5s — and otherwise release the worker and let the client
come back.

- **A navigation** gets a small self-contained HTML page that refreshes every two seconds
  and says the panel is starting. Ten people reloading now cost ten short requests instead
  of ten held workers.
- **Anything else** gets a bare `503` with `Retry-After: 2`. The panel's own `fetch()`
  would treat an HTML body as a parse error, where a 503 is a case it already handles.
- **A missing binary keeps its own answer**, with `Retry-After: 30` and the path. "Wait a
  moment" and "go and fix your install" should not be indistinguishable.

`wantsHTML()` prefers `Sec-Fetch-Mode` over `Accept`, because an XHR whose `Accept` still
mentions `text/html` is common and trusting `Accept` alone would hand a JSON caller a web
page. Where neither is sent — curl, a probe — it falls back to plain text, which is the
safe direction to be wrong in.

**And CI now parses the bridge, which it never had.** `contrib/php-bridge/` is the only
thing between a visitor and the panel on hosting with no shell, it runs on the account
being protected, and no job had ever run `php -l` over it. A syntax error would have
reached the live host and taken the panel down completely — and the bridge is exactly what
you would reach for to find out why the panel is down. Pinned to PHP 8.1, the oldest
cPanel still offers, so the bridge cannot quietly start requiring something newer.

`wantsHTML()` lives in `lib/request.php` rather than `index.php` because `index.php` begins
proxying the moment it is included and nothing in it can be required from a test. That is
why the one bridge test that existed covered `lib/path.php` and nothing else.

## D-049 — the mechanism claimed in D-048 was wrong

**Context**: the cold-start measurement D-048 was written without. It was queued three
times and bumped by deploys each time, and the entry went in anyway.

Measured on the real account, on a spare port so the live panel was not disturbed:

```
cold start to first answer: 0.113s
```

**D-048 says** each request arriving while the panel was down "sat on a worker for up to
8 seconds", and that a handful at once exhausted the account's PHP process pool. At 113ms
that does not happen. `$bootWait` was a ceiling, reached only when the panel fails to
start altogether — and an account whose panel cannot start has a different problem than
the one described.

**So the cause of the 503 remains unknown.** What is still true and still measured: the
server's own error page appeared, with its "ErrorDocument" line, which means PHP did not
run; the static site root answered throughout, which only proves static files need no
worker. Everything between those two facts was reasoning, and the reasoning has now been
contradicted by the thing it was reasoning about.

**The change in D-048 stands on a smaller claim.** A panel that cannot start no longer
holds a worker for eight seconds per request, and a browser gets a page that explains
itself instead of a connection held until the web server kills it. Both are improvements.
Neither is the explanation that entry gave, and D-048 should be read with this one.

**What to do about it**: the next 503 gets `ps` and the account's process count taken
*while it is happening*, rather than reconstructed afterwards from a log that records only
the requests that completed. A bridge that never reaches PHP writes nothing, so the
evidence for this class of failure is exactly the evidence the bridge cannot produce.

The lesson is not that the reasoning was careless — it fit every fact available at the
time. It is that the measurement which would have tested it was already written, already
queued, and was dropped three times in favour of shipping. **A pending measurement is not
a formality to get to later; it is the part that decides whether the explanation is true.**

## D-050 — a marker anyone can write is not a permission slip

**Context**: a review of the code written in this session, looking for anything that could
hand an attacker the account. One finding, and it was introduced by D-044.

D-044 excluded from the scan any directory containing `.sentinelhost-component`, so that
the PHP bridge — which lives in the document root and calls `exec()`, and is therefore
flagged by AMWScan on every cycle — would stop being reported. The justification written
beside it:

> Its presence is what tells the scanner to leave this directory alone. Not the
> directory's name — anybody can call a directory `sentinel` […] a claim only we can make
> about our own installation.

**That is false in the most ordinary way.** A file is no harder to create than a directory
name. Worse, creating a file inside the document root is *the one thing an attacker who
has uploaded a webshell has certainly already managed* — it is the premise of the whole
scenario this tool exists for. One `touch .sentinelhost-component` beside the payload and
the directory stopped being scanned, **silently and permanently**.

Two of this project's own rules were broken to build it. A name is not a path (D-026,
D-038, D-040) — restated as "a file is not a proof", which is the same error one level
along. And anything skipped is counted and reported; this was neither.

**Decision**: the marker is reported, never obeyed.

- **Nothing installs it any more.** The bridge is excluded through `limits.exclude`,
  which lives in a 0600 file outside the document root. An attacker who can edit that has
  already won by other means, so it is the only anchor worth having.
- **Every marker found is a warning naming the directory**, because the only documented
  effect that filename ever had was to hide a directory from a malware scanner. Finding
  one is finding somebody trying.
- **A warning, not a fatal error.** A configuration error stops the scan, which would let
  anyone who can write one file switch the scanner off entirely — a better outcome for
  them than the exclusion they were reaching for.

**What the review cleared**: the `sendmail` transport executes via `argv` with no shell,
from a fixed list of absolute paths or a configured one, never through `PATH`; message
headers are refused if they contain CR, LF or NUL, so an attacker-chosen filename in a
subject cannot forge a recipient; the panel's hash routing validates the tab name against
a known set before it reaches a selector; and the store's queries bind parameters, with
the only interpolation being an integer `LIMIT`.

The lesson is narrower than "review your code". Both D-044 and this entry were written
carefully, and D-044 argued *explicitly* against trusting a name — while trusting
something equally forgeable. **A convincing argument for why one thing cannot be forged is
not an argument about the thing you replaced it with.**

## D-051 — a socket that accepts is not a service that answers

**Context**: the panel on the real cPanel account went down and stayed down. The symptom
changed as it got worse: first a `503` in two seconds, which is the bridge working as
designed; then sixty seconds with no response at all, not even the bridge's own page. The
site itself answered in 0.1s throughout, so the web server was fine.

The bridge decided whether the panel was up with `fsockopen`. That asks whether the port
**accepts a connection**. A process that is wedged still holds its listening socket, and the
kernel completes the handshake on its behalf — so the probe passed, the bridge proxied the
visitor's request to it, and the request hung until the web server killed it.

Confirmed against the real binary rather than argued: with the panel stopped by `SIGSTOP`,
which holds the socket and serves nothing, `fsockopen` answers **UP in 0.00s** while a
`GET /healthz` answers **silent in 1.51s**.

This is the failure the project is named after, moved into the plumbing. `ScanStatus.
CountsAsVote()` exists because an engine that could not run has not found zero threats. A
probe that could not get an answer has not found a healthy panel. Same mistake, different
layer — and this one was written by the same hand that wrote the rule.

A wedged panel is *worse* than a stopped one. A stopped panel gets a `503` in two seconds
and the next visit starts a new one. A wedged panel holds a PHP worker on an account with a
small ceiling on them, blocks every replacement with *address already in use*, and reports
nothing to the person looking at the screen.

**Decision**: the liveness probe is an HTTP request, and what does not answer gets cleared.

- **`GET /healthz`**, answered without touching the database, the configuration lock or a
  session. Anything this handler waited on would make a panel BUSY with a scan
  indistinguishable from a wedged one, and the bridge acts on the answer by killing the
  process. The Go test uses a zero `Server` so a future dependency panics rather than
  passing quietly.
- **Any HTTP status line counts as answering**, including the `404` an older panel with no
  `/healthz` returns. The question is whether it serves, not what it thinks of the path.
- **Confirmed twice before killing.** One silent probe could be a moment of load; two, on a
  handler that waits for nothing, is not.
- **Only a verified process id is signalled.** `serve --pidfile` records it and removes it
  on a clean exit, so a file that survives means the process never shut down. Before
  signalling, `/proc/<pid>/cmdline` must show **this binary** — a pid file outlives a
  process killed hard, and Linux reuses process ids. Every doubt answers 0, and 0 is never
  signalled. Where `/proc` cannot be read, the bridge refuses and the `503` says the port is
  held by something it could not identify.
- **`TERM`, then `KILL` two seconds later.** A panel that is merely slow shuts down cleanly.
  A `SIGSTOP`ped one cannot handle `TERM` at all, which the container run above exercises:
  `TERM` does not land, `KILL` clears it, the replacement binds and answers.
- **The blocked page does not pretend to be starting**, and does not refresh itself.
  Reloading changes nothing when a port is held, and a page that keeps retrying reads as
  progress where there is none. `Retry-After` is 30, not 2.

**What this does not fix**: why the panel wedged in the first place is still unknown. The
config corruption that preceded it could not be reproduced — the TOML encoder escapes even
the exact hostile shape that broke the account (see the honest limitation recorded in
`internal/config/load_test.go`). This entry is about the bridge no longer being unable to
tell, which is a smaller claim and the only one the evidence supports.
