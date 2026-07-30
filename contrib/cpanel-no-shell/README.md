# Running SentinelHost on an account with no shell

Plenty of shared hosting accounts have no interactive shell at all. SSH key
authentication succeeds, the session opens, and the server closes it:

```text
Shell access is not enabled on your account!
If you need shell access please contact support.
```

That is a provider setting, not something you can change from your side, and asking
support to lift it may take days or may be refused. Meanwhile the quickstart assumes a
shell you do not have.

This directory is the fallback. It is not a workaround invented at a desk — it is what
was used to validate SC-006 on a real HostGator account whose shell was disabled, and it
is how every command in that validation was run.

## What it does

Your cPanel **cron entry never changes**. It calls one fixed script:

```bash
/bin/sh ~/sentinelhost/runner.sh
```

The runner executes a separate `task.sh`, and executes each distinct `task.sh`
**exactly once**. It fingerprints the file's contents, remembers what it last ran, and
exits silently when nothing has changed. So the cron entry can stay installed while you
replace `task.sh` whenever there is new work — no editing cron, no forgetting to remove
a job that keeps re-running something.

```text
~/sentinelhost/
├── runner.sh        this, called by cron        (chmod 0700)
├── task.sh          the work to do              (chmod 0600)
├── run.log          output, appended
├── .last-task       fingerprint bookkeeping
├── bin/sentinelhost
└── data/
```

## Setup

1. Upload `runner.sh` and the `sentinelhost` binary through cPanel's File Manager or
   over FTP. Set `runner.sh` to `0700` and the binary to `0755`.
2. In **Cron Jobs**, add one entry. Many shared plans enforce a **15-minute minimum**
   interval, so `*/15 * * * *` is the safe choice:

   ```bash
   /bin/sh /home/YOURUSER/sentinelhost/runner.sh
   ```

3. Upload a `task.sh`. It runs on the next tick. `example-task.sh` here is a first one:
   it configures SentinelHost against your site and prints the diagnosis.
4. Read `run.log`.

## Two things in the runner that are deliberate

**The fingerprint is written before the task runs, not after.** A task that trips a
resource limit or wedges the account must not run again on the next tick and do it
again. A task that failed has still been attempted, and repeating it automatically turns
one bad command into a loop.

**The exit code is always recorded, even when the task printed nothing.** Silence is not
evidence of success. It is the same rule that governs the scanner itself: an engine that
could not run abstains rather than reporting zero findings, and a task that produced no
output has to be distinguishable from one that succeeded quietly.

It also takes a lock, so a task that outlives its window cannot have a second copy start
on top of it — two cycles sharing one SQLite database and one quarantine vault is not a
situation worth debugging remotely — and it trims `run.log` past 4000 lines, because a
runaway log on a disk-quota-limited account is its own small outage.

## Security: read this before installing it

**A file that cron executes, and that you can replace over FTP, is an
arbitrary-code-execution channel on your account.** That is exactly the shape of the
backdoors this project exists to find. The mechanism is worth having while you are using
it, and not otherwise.

- **Keep the directory outside your document root.** Under `public_html` these files are
  reachable over the web, and a file the web can reach that cron will execute is a
  backdoor with a URL.
- **Delete the cron entry when you are done.** If you want SentinelHost running on a
  schedule afterwards, generate the proper line with `sentinelhost cron-line` — that one
  runs the scanner directly and executes nothing you can overwrite.
- **If you created an FTP account for this, delete it too**, and prefer FTPS over plain
  FTP while it exists: plain FTP sends the password and every byte in the clear.

## What this does not solve

The web panel listens on `127.0.0.1` and needs an SSH tunnel to reach, so it stays out
of reach until the provider enables shell access. Everything the CLI does — configure,
scan, inspect verdicts, quarantine, restore — works through this.
