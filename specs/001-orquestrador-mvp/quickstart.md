# Quickstart

From zero to the first scan on a shared hosting account, without root.

## Requirements

- A Linux account (cPanel or similar) with access to **cron** — SSH helps, but is not
  mandatory. If your provider has disabled the shell entirely, which is common, see
  [`contrib/cpanel-no-shell/`](../../contrib/cpanel-no-shell/): every step below can be
  driven through a single cron entry instead, and that is how SC-006 was validated.
- Nothing else. SentinelHost is a single static binary; it needs no compatible glibc,
  no systemd, no root and no installed runtime.

The *engines* it orchestrates have requirements of their own (a PHP CLI for AMWScan,
the `yara` binary for php-malware-finder). None of them is mandatory: `wp-checksums` is
native and works with the network alone, and every missing engine is reported with the
reason instead of vanishing silently.

## 1. Install

```bash
curl -fsSL https://raw.githubusercontent.com/thiagoluga/SentinelHost/main/install.sh | sh
```

The installer detects the architecture, downloads the binary, **checks the published
SHA-256** and verifies that it runs before declaring success. If the checksum does not
match, it does not install — and if `SHA256SUMS` is not available, it stops: installing
an unchecked binary is not an option in a security tool.

It needs no root and no package manager, and it runs on `sh` (dash or busybox will do —
it does not require bash).

To install somewhere else:

```bash
curl -fsSL .../install.sh | SENTINELHOST_PREFIX=~/.local/bin sh
```

### If you would rather do it by hand

```bash
mkdir -p ~/bin && cd ~/bin
BASE=https://github.com/thiagoluga/SentinelHost/releases/latest/download
curl -fsSLO "$BASE/sentinelhost-linux-amd64"    # or -arm64
curl -fsSLO "$BASE/SHA256SUMS"
sha256sum -c SHA256SUMS --ignore-missing        # check BEFORE running it
mv sentinelhost-linux-amd64 sentinelhost && chmod +x sentinelhost
```

If `~/bin` is not on your `PATH`:

```bash
echo 'export PATH="$HOME/bin:$PATH"' >> ~/.bashrc && source ~/.bashrc
```

## 2. Configure

```bash
sentinelhost config init --root ~/public_html
```

That creates `~/.sentinelhost/config.toml` with deliberately conservative defaults:

| Default | Why |
|---|---|
| Observation mode **on** | The tool reports, but moves nothing. |
| A **7-day** grace period | Time for you to calibrate weights and the whitelist before any automatic action. |
| `nice 19`, a pause between batches, a per-engine timeout | So the scanner never gets your account suspended for resource abuse. |
| Automatic purge **off** | Deleting a file of yours is always your decision. |
| The panel on `127.0.0.1` | Access through an SSH tunnel, not exposed to the internet. |

## 3. See what is available

```bash
sentinelhost doctor
```

It shows the environment, the roots, the data directory and — most usefully — **why**
each engine is or is not available. "Unavailable" with no reason would turn a solvable
problem (install the PHP CLI) into a mystery.

To install the engines that run in your user space:

```bash
sentinelhost engines --install amwscan
sentinelhost engines --install php-malware-finder   # requires the `yara` binary
```

## 4. The first scan

```bash
sentinelhost scan
```

The report shows, in this order: which engines ran (and which abstained), the verdicts
with **the votes that produced them**, and the summary per level.

Exit codes — use them in the cron to tell "found malware" from "broke":

| Code | Means |
|---|---|
| `0` | Nothing to report |
| `1` | The cycle found findings. **Not an error.** |
| `2` | An execution error |
| `3` | Another instance is already running |

## 5. Leave it running

### Without SSH (the cPanel cron)

```bash
sentinelhost cron-line
```

Copy the generated lines into the cron manager. The single-instance lock keeps two
cycles from running over each other: the second exits with code 3 without doing
anything.

### With SSH

```bash
sentinelhost daemon
```

The daemon is a comfort, not a requirement — everything it does also works with the
cron alone.

## 6. The panel

```bash
sentinelhost serve
```

The panel listens on `127.0.0.1:8787`. To reach it from your machine, **do not expose
the port** — open a tunnel:

```bash
ssh -L 8787:127.0.0.1:8787 user@server
```

Then open `http://127.0.0.1:8787`. On first access the panel asks you to set the
password — it is the only thing between the internet and a button that moves your
site's files.

## 7. Turning the automatic action on

After a few days watching what the tool finds, and having whitelisted whatever turned
out to be a false positive:

```toml
# ~/.sentinelhost/config.toml
[general]
observation_mode = false
```

From then on, and once the grace period has expired, `confirmed` verdicts start being
quarantined automatically. Levels below that always keep waiting for your decision.

## Restoring something

Nothing is deleted. Every item in the vault comes back byte for byte:

```bash
sentinelhost quarantine list
sentinelhost quarantine restore q_20260723150405_a1b2c3d4
```

To check that the whole vault is still intact — before the moment you need it:

```bash
sentinelhost quarantine verify
```

## Alerts

```bash
sentinelhost alert --test-email
sentinelhost alert --test-webhook my-hook
```

The result shown is the server's **real error**. Finding out that your hosting blocks
port 587 is the entire purpose of these commands.

## Where things live

```text
~/.sentinelhost/
├── config.toml        the configuration (the source of truth, shared with the panel)
├── sentinelhost.db    verdicts, quarantine, deliveries, the structured log
├── baseline.json      hashes for the incremental cycles
├── quarantine/        the vault — neutralized files, all of them restorable
├── raw/               the engines' raw output, for auditing
└── engines/           engines installed in your user space
```

## Uninstalling

```bash
sentinelhost quarantine list        # restore whatever you want first
rm ~/bin/sentinelhost
rm -rf ~/.sentinelhost              # this deletes the vault too; check first
```
