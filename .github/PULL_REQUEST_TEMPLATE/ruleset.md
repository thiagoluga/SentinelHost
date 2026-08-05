<!--
Submitting a ruleset for the catalogue. Read catalog/README.md first.
Open this template with: ?template=ruleset.md
-->

## The ruleset

- **Upstream:**
- **Licence (SPDX):**
- **What it detects:**

## The checks CI cannot do

CI verifies the URL is immutable, the digest matches what is actually served, and the
weight is below the ceiling. **It cannot read the rules.** These are the parts a human has
to answer, and they are the reason this is reviewed at all:

- [ ] **The rules do not match files every site has.** A rule firing on `wp-config.php`,
      `index.php` or `wp-load.php` would make SentinelHost quarantine every site that
      installed this — a better attack than writing a webshell, and it needs no code
      execution. Say what you grepped for.
- [ ] **The upstream is a project, not a gist.** It has a history, a reachable author, and
      a reason to still exist next year.
- [ ] **The licence permits redistribution**, and is stated correctly. Non-commercial
      licences are accepted; they are shown to the user before installing.
- [ ] **The weight is 0.5 unless there is evidence.** A false-positive rate measured
      against real sites is evidence. "The rules are good" is not.

## What I ran

```
# the grep for filename matches, and its output
```

<!--
A submission that cannot be reviewed on these terms is declined. That is not a judgement
about the ruleset — it is that "we approved it" has to mean something.
-->
