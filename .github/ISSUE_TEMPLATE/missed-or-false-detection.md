---
name: It missed something, or flagged something clean
about: The verdict was wrong
labels: detection
---

<!--
This is the report that matters most here. A scanner that misses is worse than no
scanner, because it manufactures confidence.

Do NOT attach the malware itself. A hash and the rule that fired are enough to start.
-->

**What happened**

- [ ] It missed a file that is malicious
- [ ] It flagged a file that is clean

**The verdict**

Open the finding in the panel and paste the votes — the engines, weights and rules. That
block is the whole reason it exists: it answers "why did it decide this".

```
level, score, and the vote lines
```

**The file**

- SHA256:
- Where it sits (inside a document root? under `.trash`? outside both?):
- What it is, if you know (a webshell, a minified library, a plugin's own cache):

**Coverage**

Findings are only as good as what was scanned. From the same cycle:

```
files_considered / files_scanned, and any skipped_reason_counts
```

If an engine abstained, say which — an abstention is not a clean result, and it is the
most common reason for a miss.
