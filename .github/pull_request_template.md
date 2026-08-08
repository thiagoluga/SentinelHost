<!--
Submitting a ruleset for the catalogue instead? Use the other template:
?template=ruleset.md

Delete any section that does not apply. An empty heading is worse than no heading.
-->

## What changes, and why

<!-- The behaviour, not the diff. The reviewer can read the diff. -->

## How it was verified

<!--
This project has a specific history: nine defects were found by running the real thing,
and eight of them were an assumption about external behaviour plus a test written to
confirm that assumption. They all passed. See DECISIONS.md D-022.

So: what did you actually run, and what did it print? A captured output beats a claim.
-->

- [ ] `make test` passes
- [ ] `make lint` passes
- [ ] Ran on Linux (`make test-linux`), not only on a workstation — POSIX permissions
      have hidden two defects that a green Windows suite said nothing about
- [ ] `make validate-engines`, if this touches an engine's command line or output format

## If this changes what a scan reports

- [ ] An engine that could not run **abstains**; it never counts as having found nothing
- [ ] Anything skipped is **counted and reported** — silent truncation reads as full
      coverage
- [ ] The verdict still carries its votes, weights and rules, so "why was this file
      quarantined?" has an answer

## Anything a test cannot check

<!--
Which assumption would break this, what you chose not to do, what you could not verify.
Naming a limitation here is worth more than a paragraph claiming there is none — and it
is the part of the PR the maintainer reads first.
-->

## Housekeeping

- [ ] Everything committed is in English (Principle VIII — the conversation can be in any
      language, the artifacts cannot)
- [ ] Conventional Commits
- [ ] `CHANGELOG.md` updated, if a user would notice this
- [ ] `DECISIONS.md` updated, if the spec left room and you chose an interpretation
