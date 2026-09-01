<!--
Title: what changed, and end it with the issue number — e.g.
    fix(history): a one-branch fetch is not an all-clear (issue #27)
-->

**In one line:** what was wrong before this change.

Closes #

## What it does

<!-- The change itself. If it touches the judgment path, say which of the five
     exit codes the tool now returns where, and why that is the true one. -->

## How it was checked

<!-- What you ran and what you saw. "Measured, X" means someone observed X.
     If you could not reproduce something you expected to, that is worth saying. -->

## Anything this does not fix

<!-- Limits are welcome here. A stated limit is cheaper than one someone finds
     later, and it is often the next issue. -->

---

- [ ] `pytest -q` passes locally
- [ ] For each new test: I reverted the thing it names, in a copy, and watched it
      fail. (This repository's most common defect is a test that passes for the
      wrong reason — see [CONTRIBUTING.md](../CONTRIBUTING.md).)
- [ ] If this touches the ref-coverage probe, the invariants in CONTRIBUTING still
      hold, and the PR says which one it came near.
