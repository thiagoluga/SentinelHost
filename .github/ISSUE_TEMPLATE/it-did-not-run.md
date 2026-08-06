---
name: It did not run, or ran and did nothing
about: Installation, cron, engines, or a cycle that scanned nothing
labels: environment
---

<!--
Almost every problem in this class is the environment, not the code — and the environment
is exactly what the maintainer cannot see. The commands below are what make it visible.
-->

**Where it runs**

- Hosting (cPanel / Plesk / DirectAdmin / a VPS / something else):
- Shell access:  yes / no
- `uname -a`:

**What the tool says about the environment**

```
sentinelhost doctor
```

```
sentinelhost engines
```

`doctor` is written to answer this question, so please run it before describing symptoms —
it usually names the cause directly.

**What happened**

```
the command you ran, and its complete output
```

**Was anything scanned?**

```
files_considered and files_scanned from the report
```

Zero considered means the walk found nothing — usually `general.roots` or a permission,
not detection.
