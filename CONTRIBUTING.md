# Contributing to DepTrail

Thanks for looking. This file is short on process and long on the two things that
are specific to this repository: **what a verdict means**, and **how to tell
whether a test is real**. Both have cost us defects, and neither is discoverable
from the code.

## Running it

```bash
python -m venv .venv && . .venv/bin/activate     # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
pytest -q
```

`git` must be on `PATH` — every scan shells out to it. The [GitHub CLI](https://cli.github.com/)
is needed for the scans that read CI runs or secret names. The suite stubs `gh`
rather than calling it, with one known exception that is tracked as
[#114](https://github.com/Official-Space-AI/deptrail/issues/114) — a good example
of the section below, since that test passes on CI for a reason unrelated to its
name.

To see the whole judgment flow without a network, a token, or an incident:

```bash
deptrail demo
```

CI runs `pytest -q` on Linux, macOS and Windows, on Python 3.10 and 3.13. The
Windows job is the one that catches path assumptions, so if you are adding a test
that writes a path, think about whether the name is legal there.

## The exit codes are a contract

```
0  absence of exposure was established
1  credentials to rotate
2  looked, and could not prove absence
3  the request was malformed
4  the tool could not run; retrying may help
```

Almost every defect found in this repository has been a verdict moving between
**0** and **2** — not a crash, not an exception, a wrong number returned quietly by
a green test suite. When you change anything in the judgment path, the question to
answer in your PR is *which of these five sentences the tool now says, and is it
true*.

Two rules follow from it:

- **`0` is a claim, not a default.** If the scan could not read something, could not
  reach something, or could not tell two situations apart, it may not exit 0. When
  in doubt the answer is 2.
- **Do not widen a caveat into a verdict or narrow a verdict into a caveat** without
  saying so. A caveat that should block is a false all-clear; a block that should be
  a caveat makes the tool useless, which is the same bug pointing the other way.

## A test has to fail when the thing it names is reverted

This is the most common defect in this repository's history, by a distance. A green
test that proves nothing is worse than no test, because it stops anyone looking
again. Real examples, all of which passed:

- a fast path answered before the query the test was written for ever ran
- a fixture was deterministic, so two "different" remotes produced identical commit
  ids and the test could not tell them apart
- `conftest.py` set an environment variable that made a defence unnecessary, so the
  test passed with the defence deleted
- a lookup fell back to the developer's real `gh` login, so an assertion about an
  environment variable was satisfied by something else entirely
- a test reached the real `github.com` on every run

**So: before you push a test, break the thing it tests and watch it fail.** Copy the
tree somewhere else, revert the guard, run that one test. If it still passes, the
test is not testing what its name says. This takes a minute and it is the single
most useful minute in the workflow.

```bash
cp -R . /tmp/mutant && cd /tmp/mutant
# revert the guard, then:
PYTHONPATH=/tmp/mutant/src pytest -q -k the_test_you_just_wrote
```

Mutate a copy, never your checkout — it is very easy to commit the mutation.

## Claims are measured

Commit messages and PR bodies in this repository say what was observed, not what is
believed. "Measured, X" means someone ran it and saw X. If you write that a change
closes a hole, close it in a scratch directory first and say what you saw; if you
cannot reproduce the hole, say that too — "I could not construct this" is a useful
sentence and an honest one.

The same applies to comments. A comment that says a setting blocks something, when
the setting is a no-op, is worse than no comment: we removed one of those recently
after measuring that an environment variable outranked it.

## Things a change must not quietly reverse

The ref-coverage probe holds a small set of invariants. Each was added after
something went wrong, and each is easy to undo by accident:

- **The probe does not read the configuration of the repository under investigation.**
  That config is input from a possibly-compromised source; `core.sshCommand` and
  `remote.<name>.uploadpack` were both measured executing a planted value.
- **It cannot be *asked* for a credential.** `credential.helper` is empty. With a
  helper reachable, a stale token drew a 401 and git then ran `credential erase`,
  deleting the operator's saved GitHub login — from an ordinary run, and from
  `pytest`.
- **A credential goes only to an address the operator named**, never to one read out
  of the checkout, never over plain http, and never onward through a redirect.
- **`GIT_ALLOW_PROTOCOL` is intersected with what it inherits, never widened.**
- **The set of refs used for coverage is the set the walk enumerates.** If those
  drift apart, coverage vouches for refs nobody walked.

If your change touches one of these, say in the PR which one and why it still holds.

## Scope and shape of a change

- **Open an issue before writing code**, and keep it to one issue per pull request.
  Put the number at the end of the PR title: `fix(history): … (issue #42)`.
- Small is better. A 79-line change on this repository once carried the same defect
  density as a 1,374-line one, so size is not the risk — but a reviewer's attention
  is finite, and a PR that does two things gets half the attention on each.
- Commit messages: a summary line that says what changed and why it was wrong
  before. The history is meant to be readable as an argument.

## Reporting something instead of fixing it

That is welcome and often more valuable. See [SECURITY.md](SECURITY.md) if it is a
security issue. Otherwise open an issue with what you ran, what you expected, and
what you saw — the wrong-verdict template asks for exactly the fields that make a
report reproducible.

## Licence

By contributing you agree that your contributions are licensed under the
[Apache License 2.0](LICENSE), the same terms as the project.
