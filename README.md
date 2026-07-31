# SentinelHost

**An open source malware-scanner orchestrator for shared hosting.**

SentinelHost **is not an antivirus** and **has no detection engine of its own**. It
coordinates existing open source engines (AMWScan, php-malware-finder through YARA,
maldet, plus integrity verification against the official WordPress.org checksums),
normalizes all of their output into a single schema and consolidates everything into
one **weighted consensus verdict**.

The question it answers is not "is this file malware?" — it is "how many independent
engines agree that this file is malware, with what weight, and under which rule?".

## Why orchestrate instead of compete

Every PHP malware scanner has different blind spots. Running one means accepting its
false negatives; running several means having to interpret N reports in incompatible
formats. SentinelHost runs whichever ones are available in your environment,
cross-checks the results and delivers **one** verdict per file — with the votes in
plain sight.

GPL engines are invoked exclusively as **external processes through their CLI**,
never linked, which lets the orchestrator keep an MIT license.

## Principles

These are non-negotiable and recorded in
[`.specify/memory/constitution.md`](.specify/memory/constitution.md):

1. **Reversibility above all** — quarantine is move + record + block. Never delete.
   A false positive never takes your site down permanently.
2. **Orchestrate, do not compete** — zero signature database of our own.
3. **It works without root** — a cheap hosting account, no systemd, possibly no SSH
   (a fallback through the cPanel cron).
4. **A polite citizen of the hosting** — `nice 19`, pauses between batches, an
   incremental scan and a per-engine timeout, all active **by default**.
5. **Transparent consensus** — every verdict shows the engines, weights and rules.
   An automatic action happens only at the `confirmed` level.
6. **The normalized schema as a contract** — an adapter failure becomes an
   abstention, never a "clean vote" and never a dead cycle.
7. **Operational simplicity** — one static binary, one TOML, SQLite without CGO, an
   embedded panel.
8. **English is the language of the repository** — code, comments, messages,
   documentation and commits. Shared hosting exists everywhere, and a contributor in
   Jakarta or Lagos has to be able to read the code without a translator.

## Current state

In development — feature `001-orquestrador-mvp`. See
[`specs/001-orquestrador-mvp/`](specs/001-orquestrador-mvp/) for the specification,
the plan and the tasks, and [`SUMMARY.md`](SUMMARY.md) for what is already
implemented.

## The MVP's engines

| Engine | Type | Requirements | Consensus weight |
|---|---|---|---|
| `wp-checksums` (native) | Integrity through the official WordPress.org API | Network only | 1.5 |
| `maldet` | Signatures + hex | The `maldet` binary (a system package; it cannot be installed without root) | 1.0 |
| `amwscan` | Pure-PHP scanner (phar) | PHP CLI ≥ 7.1 | 0.8 |
| `php-malware-finder` | YARA rules | the `yara` binary on PATH | 0.8 |

All four are implemented. `wordfence-cli` and `clamav` are left for after the MVP.

maldet is the one SentinelHost cannot install for you: it ships as a system package
that wants root. When it is absent the engine abstains with a reason you can act on,
and the consensus proceeds with the others. Its own quarantine and cleaner are
disabled on every invocation — they are not reversible from our vault (`DECISIONS.md`
D-025).

### If maldet is installed and still abstains

Two host settings gate it, and **both are off in a default maldet install** — so on
most shared hosting maldet is present and unusable until someone changes them. Neither
is something you can do from your own account, so `sentinelhost engines` prints the
line to forward to your hosting support:

| What you will see | What the admin has to do |
|---|---|
| `scan_user_access` is 0 | set `scan_user_access="1"` in `/usr/local/maldetect/conf.maldet` |
| its per-user paths do not exist yet | run `maldet --mkpubpaths` as root, or wait for maldet's own `cron.pub` |

The reason they are reported separately is that maldet answers **both** with its
version banner and exit code 0. Read as success, that makes the engine look healthy
while it is refusing to scan anything — the one failure mode this project treats as
worse than having no scanner at all.

## Where a finding sits changes what happens to it

A webshell in the document root can be executed by anyone with the URL, this minute. The
same webshell in the account's trash cannot be executed by anybody. That is a real
difference in urgency, and every verdict now records which one it is:

| `location` | Meaning |
|---|---|
| `web_reachable` | inside a document root — a visitor can request it |
| `trash` | the control panel's deleted-files area |
| `outside_docroot` | on the account but not served — backups, a home directory |
| `unknown` | no document root configured, so nothing is claimed |

**It changes the action, never the verdict.** A file the web does not serve keeps its real
level, its votes and its place in the report; what it does not get is an automatic
quarantine, because moving a file out of the trash and into our vault swaps one holding
area for another without reducing any risk. The reason travels with it, as
`skipped_not_reachable`.

Adjusting a score by context is how real findings quietly stop being seen, so the score
is not touched. This acts where the whitelist acts (`DECISIONS.md` D-006).

**And unreachable is not safe.** The trash restores with one click: restoring the site
restores whatever is in it. `unknown` counts as reachable for the same reason — when the
question was never answerable, the safe reading is the urgent one.

Set `document_roots` in the TOML when your scan covers more than the site does. Without
it, the scanned roots are assumed to be served, which can only ever classify more files
as reachable than the truth.

## Notifications — what exists today

| Channel | State |
|---|---|
| **E-mail (SMTP)** | Ready. An immediate alert per level plus a periodic summary, with a test send that shows the server's real error. |
| **Generic webhook** | Ready. A signed JSON `POST` with HMAC-SHA256, 5 attempts with backoff, a delivery history. |
| **n8n, Zapier, your own endpoint** | Ready, with the generic webhook (`format = "raw"`). |
| **Slack** | Ready. Set `format = "slack"` on the webhook and the body is shaped for a Slack incoming webhook, with the votes in the message. |
| **Discord** | Ready. `format = "discord"`, capped at Discord's 2000-character limit. |
| **Telegram** | Post-MVP, declared in the spec. |

Slack and Discord do not verify signatures, so the HMAC only means something for
`format = "raw"` — the configuration warns if you set a secret on the others. File
paths reaching a chat message are escaped: a file named `<!channel>.php` is a
legitimate filename and would otherwise make your own alert ping the whole
workspace.

The webhooks' complete contract is in
[`contracts/webhooks.md`](specs/001-orquestrador-mvp/contracts/webhooks.md).

## Installation and use

See [`specs/001-orquestrador-mvp/quickstart.md`](specs/001-orquestrador-mvp/quickstart.md).

```bash
sentinelhost scan --root ~/public_html
sentinelhost serve
```

### If your host gives you no shell

Plenty of shared accounts have SSH disabled by the provider — key authentication
succeeds and the session closes with `Shell access is not enabled on your account`.
[`contrib/cpanel-no-shell/`](contrib/cpanel-no-shell/) is the fallback: one unchanging
cron entry calls a fixed `runner.sh`, which executes a replaceable `task.sh` exactly
once per distinct content. Everything the CLI does works through it. SC-006 was
validated that way, on an account with no shell at all.

And for the panel, [`contrib/php-bridge/`](contrib/php-bridge/) makes it behave the way
WordPress does — open the URL and it is there. The mechanism is the one WordPress
actually uses: nothing runs continuously. A small PHP file starts the panel if it is down
and proxies to it, so a host that kills long-lived processes stops mattering.

## Design documentation

- [`docs/schema-and-adapters.md`](docs/schema-and-adapters.md) — the normalized
  schema and the adapter contract (the heart of the project)
- [`docs/panel-mockup.html`](docs/panel-mockup.html) — the web panel's visual
  reference
- [`DECISIONS.md`](DECISIONS.md) — decisions taken where the spec was ambiguous

## License

MIT — see [`LICENSE`](LICENSE).
