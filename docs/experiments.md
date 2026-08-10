# Experiments

Unit tests check the scenarios we imagined; reviews check the code we wrote.
Neither catches an assumption about the world that is simply wrong. Every stage
of this project therefore has to survive a replay against real data, and the
findings below are the reason that rule exists.

Each entry records the assumption under test, what actually happened, and what
changed as a result.

## E1 — Do CI run records name the commit we walk?

**Assumption**: `gh run list --json headSha` returns the commit a run checked
out, so grading can match runs to exposing commits by SHA.

**Method**: read the 12 most recent runs of this repository, including
`pull_request` runs, and check each `headSha` against local history.

**Result**: every `headSha` resolved to a real branch commit, `pull_request`
runs included — the match by SHA holds. But GitHub checks out an ephemeral
*merge* commit for `pull_request` events, so what such a run installed is the
merge of head and base, not the head snapshot alone.

**Change**: grading matches on `headSha` as designed; the merge-commit caveat is
documented as a limitation of what a PR run can confirm.

## E2 — Are look-alike lockfile names a real hazard or a hypothetical one?

**Assumption**: rejecting names like `sample-package-lock.json` guards against a
mistake nobody actually makes.

**Method**: search public repositories for committed files whose name resembles
a lockfile.

**Result**: the search returns almost nothing *but* look-alikes —
`package-lock.json.old`, `package-lock.json.backup2`, `package-lock.json~2`,
`___package-lock.json_1`, `oh-package-lock.json5`, and one repository holding
five timestamped copies (`package-lock.json.140190139`, …). Real lockfiles are
excluded from code search indexing, so the corpus reachable that way is entirely
stale backups.

**Change**: none needed — the exact-basename rule already excludes them. The
experiment converted a defensive guess into a measured hazard: a stale backup
pinning a compromised version would otherwise be reported as an exposure that
never ends.

## E3 — Does the walker judge a real repository correctly? (found two bugs)

**Assumption**: the interval logic validated on synthetic repositories
generalises to real history.

**Method**: clone `axios/axios` (2,167 commits, 191 lockfile changes, 11 refs),
extract the true version history of `follow-redirects` straight from git, and
compare the walker's verdict against it for six windows.

**Result 1 — false clean, the worst failure mode.** A window inside a two-day
exposure returned CLEAN. The commit that pinned the version
(`c5bdbd4`, *"Update follow-redirects dependency due to Vulnerability"*) arrived
through a merge, so it was not on any first-parent chain; the walker treated it
as a three-minute point instead of an interval. Every repository that merges
pull requests has this shape, and no synthetic fixture had it, because all of
them were linear.

**Result 2 — unusable on real input.** The first fix paired intervals with one
`git merge-base --is-ancestor` process per candidate: the same scan then failed
to finish in two minutes.

**Result 3 — my "ground truth" was wrong.** A five-minute window looked like a
revert gap where the version was briefly absent, and the walker called it
EXPOSED. Checking ancestry showed the two commits are *siblings of one parent*,
not a revert: at that instant one line pinned 1.14.8 while another pinned
1.14.7. The date-ordered history I had built was not ground truth at all — it
interleaved parallel branches. The walker was right and the expectation was
wrong.

**Result 4 — warnings that swallowed the verdict.** Comparing consecutive
commits in topological order flagged ordinary branching as clock skew, which
made unrelated windows INDETERMINATE and printed the same warning once per ref.

**Changes**: intervals are now computed over each ref's full ancestry and closed
by the first *descendant* that stops pinning a named version (deletion included);
ancestry is answered in process from a single `rev-list`; skew is detected
against a commit's own parents, not its topological neighbours; warnings are
deduplicated per repository.

**Verification**: six windows, six matches — including the two that had been
wrong — at roughly 7 seconds per query over that history. Regression tests cover
the merge-borne exposure and the deletion boundary.

## E4 — Can a run be shown to have installed the dependencies?

**Assumption**: reading a run's step names through `gh run view` tells us whether
it installed dependencies, which `CONFIRMED` depends on.

**Method**: resolve step names for real runs in this repository and in
`axios/axios`, then compare against what those workflows actually do.

**Result**: two problems. Some runs return `{"jobs": []}` — queued, skipped, or
past their job retention — and the first implementation read that empty list as
"installs nothing", a false statement in the evidence text. And real step names
do not carry the command: axios installs in steps named `Install (pass 1)` and
`Clean and reinstall (pass 2)`, which no honest hint list matches, while a step
named `Install` in another repository might install anything at all.

**Change**: install detection reads the workflow files **from git at the run's own
commit** instead of the API. They are versioned alongside the lockfile, so the
answer matches what that commit's CI would have run, needs no network, no token,
and no run retention. Only unambiguous commands (`npm ci`, `npm install`, `yarn
install`, `pnpm install`, …) return `True`; anything else is `False` or `None`,
and neither can raise a grade to `CONFIRMED`.

**Verification**: `axios/axios` at HEAD → `True` (its workflows run `npm ci`);
this repository at HEAD → `False` (it installs with pip); axios's root commit,
which has no workflows → `None`.

## E5 — Does run metadata survive re-runs?

**Assumption**: `startedAt` is when the install happened.

**Method**: read `createdAt` alongside `startedAt` for real runs and check how
they relate.

**Result**: they are identical for every run in this repository, so nothing is
visible here — but GitHub rewrites `startedAt` when a run is re-run, which would
move an install out of the window it actually happened in.

**Change**: a run's effective time is the earlier of `createdAt`/`startedAt`, so
a re-run months later cannot erase an in-window install. Covered by a regression
test rather than by this experiment, which could only establish that the field
exists and is populated.
