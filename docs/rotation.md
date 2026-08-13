# The rotation list

The scan exists to answer one question: **which credentials must be rotated?**
Everything else — the interval judgment, the CI correlation, the grades — is in
service of making that list short enough to act on and complete enough to trust.

Two errors are possible and they are not symmetric. Rotating a credential that
was never at risk costs minutes. Leaving one live in an attacker's hands is the
incident repeating. So the list narrows only where evidence supports narrowing,
and every entry names the reason it is there.

## How scope is decided

| Scope | When | What is listed |
|---|---|---|
| `WORKFLOW` | A specific run is implicated and its workflow file names the secrets it can reach | Exactly those secrets |
| `REPO_WIDE` | A run is implicated but its scope cannot be narrowed — `secrets: inherit`, an unreadable workflow, an unknown workflow path, or an unreadable repository history | Every secret the repository can see |
| `DEVELOPER` | No run is implicated at all | The repository's secrets, plus the note that whoever installed it locally held those credentials and no log will prove it |

Scope is read from the workflow files **at the exposing commit** — the same files
the grader reads for install evidence — because they state which secrets those
runs could see. Every implicated workflow counts, not just the first: one push
fires several, and each one's environment held its own credentials. Local
reusable workflows (`uses: ./.github/workflows/deploy.yml`) are followed, since a
caller often names nothing while the callee reads the deploy token; a reusable
workflow in another repository cannot be read, so it falls back to `REPO_WIDE`.

Only text inside `${{ ... }}` counts as a reference. A commented-out secret or
the literal string `"secrets.FOO"` in an echo is not an access, and listing it
would put a credential nobody used on the list.

Secrets defined on a GitHub **environment** resolve through the same syntax but
do not appear in a repository secret listing, so any environment an implicated
run entered is named in the report as something to check separately.

Only secret *names* are ever read; values are not accessible through the API by
design, and this tool never asks for them.

## What stays off the list

- **Repositories with no overlapping exposure in a tree a workflow installs.**
- **Fixture and example lockfiles.** A lockfile under `tests/fixtures`,
  `examples`, `spec`, `testdata`, `vendor` or `node_modules` is committed data.
  Those findings appear in the report under "set aside" with their paths, so the
  classification is visible and reversible, but they raise no credentials.
- **A workflow that reads no secrets.** The finding stands; there is simply
  nothing to rotate from it.

## Two ways of not knowing, two different answers

Both are refusals to claim an all-clear, and they are deliberately not the same
refusal, because "rotate" and "I could not look" are different instructions.

**Evidence about a lockfile we do track was lost** — an unreadable snapshot, a
lockfile that failed to parse, a path discovered with no walkable history. A pin may
be hidden there, so the repository is graded `POSSIBLE` and cannot be cleared.

Whether that *widens* the rotation list depends on there being a list to widen. When
something was found, every credential the repository can reach goes on it with the
reason: a second, unreadable tree is exactly the reason the found scope cannot be
trusted as complete. When **nothing** was found, no credential is named — no evidence
points at one, and "rotate everything you own" is a false alarm rather than caution.
The run exits `2` and says what it could not read.

**The clone itself held less than the repository does** — shallow (including the
default `actions/checkout`, which fetches depth 1), partial (`--filter=blob:none`,
which has the commits but not the blobs), or single-branch (a refspec with no
wildcard, so "every ref testifies" is false). Each is named, each forces exit `2`, and
none of them raises a credential. The remedy is a deeper clone, which is why this is
kept apart from an unreadable artifact: nothing fixes a corrupt lockfile, and
`--allow-incomplete-history` may waive only this kind — off by default, and the reason
is printed either way.

This distinction exists because the alternative had a property no responder should have
to reason about: **deepening a clone lowered the reported risk.** A shallow clone
exited `1` and asked for the whole secret store; the same repository cloned in full
exited `0`. Both independent reviews of #16 found it, and the field agrees on the shape
of the fix — OSV-Scanner puts "found nothing to analyse" outside its result range
entirely and requires `--allow-no-lockfiles` to downgrade it, and Snyk's
`strictOutOfSync` refuses by default.

**There was no lockfile we could read at all** — a tree locked with Yarn, pnpm,
Bun or Deno, present while the malicious version was installable. Nothing was seen,
and nothing was hidden from us either: no version, no window overlap, no run. Such a
tree is listed under **not judged** with the file that caused it, the report refuses
to prove absence, and the run exits `2`. It raises no credentials, because grading it
`POSSIBLE` would hand every Yarn user a list of their entire secret store — a false
alarm, not caution.

A tree with *no* lockfile at all belongs in this category too and is not yet reported;
see issue #22 for why that needs npm's workspace rules to answer correctly.

A lockfile of either kind under `tests/fixtures`, `examples` and the like is
committed data: it is named in the caveats and does not cost the repository its
verdict, the same treatment a fixture exposure gets.

## One sentence per repository, not one per package

A list long enough to be unactionable is a failure, not thoroughness — and the
report used to break that rule on its own output. A repository is scanned once per
package the advisory names, so a caveat about the repository was reached once per
package: three packages pinned in one lockfile printed the same paragraph three
times, and the September 2025 Shai-Hulud advisory named roughly 180 packages.

This section describes the rotation list and the caveats block. One producer is not
converted yet and is named at the end.

Deduplicating the rendered lines could not fix it, because the lines were not
identical: each one carried its own version number, which is exactly the evidence a
responder checking a machine by hand needs. So a caveat is stored as a sentence plus
the **subjects** it covers, and the varying part never enters the prose:

```
rotate (1 repository to rotate broadly)
  [could not be named] r2: pinned in package-lock.json, and no CI run was implicated — so any
                install happened outside CI; Actions secrets are not automatically present on a
                developer machine, but the same values often are, so investigate that machine's
                credentials as well — and this repository's secret names could not be listed, so
                rotate everything it can see (covers chalk@5.6.1, debug@4.4.2,
                ansi-styles@6.2.2)
```

Merging then compares sentences exactly instead of guessing at prose, and every
version survives. The same grouping merges the reasons behind one credential
implicated by several packages: joining the prose and deduplicating its clauses used
to drop the tail of every sentence after the first, so the second package's reason
ended mid-thought.

Two consequences worth knowing:

- **The rotate section prints both halves of the list.** Named credentials and
  repositories whose secret names could not be listed appear together, and the
  heading counts both. Printing the second only when the first was empty meant one
  repository naming a credential could hide another repository's repo-wide risk.
- **The rotation list and the caveats block fold at 96 columns** with a hanging
  indent, never truncated. Merging 180 subjects onto one line produced a 3.3 kB
  line, which is unreadable for the same reason the repetition was. (The timeline's
  evidence lines are not folded and can still run past 96; they are one fact each,
  and they did not change here.)

  Two things the fold deliberately does *not* do, with the measured limits rather
  than the intended ones:

  - **It never breaks a word**, so a secret name or a `package@version` survives
    intact for `grep`. The continuation indent counts against the width, so the
    longest run of non-whitespace that can be kept *and* hold the line to 96 columns
    is **80** characters; a longer one is still kept whole and its line runs over —
    an 82-character lockfile path produces a 99-column line. The unit is the
    whitespace-delimited run, not the path, so trailing punctuation counts against
    it. A path containing whitespace is therefore the exception: it is not one run, a
    long enough one is folded at its space, and the exact path string will not be
    found in the output.
  - **It never folds the identity that opens a line** (grade, repo, secret, scope,
    run ids). A long repository and secret name together can push that line past the
    width; it takes a line of its own rather than pushing the body over too.

Two things are **not** solved by this, both measured:

- **One caveat still prints once per package.** The CI-retention note bakes a
  per-package timestamp into its prose, and the useful merged form is a single
  earliest instant rather than a list of them, which makes it a semantics change
  rather than a rendering one. See issue #33.
- **At monorepo scale the rotation list is still too long to act on.** Grouping works
  within one credential, so eight credentials implicated by the same 50 lockfiles ×
  180 packages print that evidence eight times: 16,414 lines for eight actions. It is
  4.2× smaller than before the grouping — which produced 14 lines of roughly 440 kB
  each — and still not actionable. Fixing it means grouping *items* by identical cause
  set and treating the lockfile path as a subject rather than as prose, the same
  lesson one level up. See issue #35.

## What the report refuses to claim

A report says it **cannot prove absence** whenever a repository failed to scan, a
tree could not be read, or the advisory declares partial coverage. In each case
something was not looked at, and "nothing found" would be the wrong sentence to
hand a responder.
