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

**Change**: grading matches on `headSha` as designed, but only for events that
check out the head commit (`push`, `workflow_dispatch`, `schedule`, `release`). A
`pull_request` run installs the merge of head and base, so it can support a grade
and never confirm one. Later measurement (E6) showed why the allow-list matters.

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

## E6 — Does the collector actually see the runs that matter?

**Assumption**: reading the most recent 200 runs is enough to find the one that
installed the malicious version.

**Method**: query real run history for a date range through the API, for this
repository and for `axios/axios`.

**Result**: `axios/axios` produced **297 runs in nine days** — three pages. Any
fixed "recent N" cap would have silently dropped the older runs in a busy
repository, which is exactly where an incident lands. The same query also
surfaced event types the grading rules had not considered: `issue_comment`,
`issues`, `pull_request_review_comment`, and `dynamic`. Those runs carry the
default branch's `head_sha` but execute a workflow that may install nothing, so
attributing another workflow's `npm ci` to them would have confirmed an
execution that never happened.

**Changes**: the collector asks for an explicit date range and follows every page,
so coverage is *what was requested* rather than an inference from page fullness.
Install detection now reads only the workflow file that defines the run
(`workflow_runs[].path`), not every workflow at that commit. Events outside the
head-checkout allow-list cannot confirm.

**Verification**: the range query returns 7 runs for this repository and 0 for a
range with no activity; `axios/axios` returns all 297; per-workflow detection
answers `True` for a `ci.yml` running `npm ci` and `False` for a `docs.yml`
beside it at the same commit.

## E7 — Does an end-to-end org scan produce a usable rotation list?

**Assumption**: with the walker, the advisory loader and the grader in place, a
scan of a real organization needs only to be wired together.

**Method**: clone this organization's repository, load a live advisory, read real
CI runs for the window through the API, read real secret names, and render the
report.

**Result**: it ran, and it flagged **this project's own test fixtures** —
`tests/fixtures/v1|v2|v3/package-lock.json` each pin `chalk 5.6.1`, which is a
correct finding under the rules and useless to a responder. Fixture and example
lockfiles are committed data, not a tree any workflow installs, and letting them
raise credentials would bury the real items in a list nobody can act on. The
same scan also confirmed the grading path end to end: the runs were graded
`LIKELY` rather than `CONFIRMED` because this repository's workflow installs pip
dependencies, not npm ones.

**Change**: exposures under fixture, example, spec, sample, testdata, vendor and
`node_modules` directories are **set aside, not dropped** — they appear in the
report under their own heading with the reason, so a human can overrule the
classification, but they produce no rotation items and do not raise the report's
grade.

**Verification**: the same scan now reports "no exposure found in an installed
tree", lists the three fixtures under "set aside (3)", and rotates nothing, while
a root lockfile in the same shape still produces a `CONFIRMED` finding and a
narrowed rotation list.

## E8 — Does secret extraction hold on real workflows?

**Assumption**: a regex over workflow files finds the secrets a run could reach.

**Method**: clone `axios/axios` and `sindresorhus/got`, extract secrets from every
workflow at HEAD, and compare against a raw grep of the same files.

**Result**: extraction matched the raw grep on all nine workflows, and the two
that reference `GITHUB_TOKEN` are correctly excluded from the rotation list as
ephemeral. The experiment also surfaced a gap the code did not cover: axios's
`publish.yml` declares `environment: npm-publish` and publishes through OIDC.
Secrets defined **on a GitHub environment** resolve through the same
`secrets.NAME` syntax but are not returned by a repository secret listing, so the
REPO_WIDE fallback would have missed them silently.

**Change**: an implicated workflow's `environment:` declarations are named in the
report with the reason, so a responder knows to check that environment's secrets
separately.

**Verification**: the extraction comparison above, plus a regression test for a
job with `environment: production`.

## E9 — Can an evaluator reproduce the judgment on a clean machine?

**Assumption**: the demo works because it works on the machine that wrote it.

**Method**: create an empty virtualenv, install the package from the checkout —
the same path the README's `pip install git+https://…` line takes once the source
is fetched — and run the demo with no GitHub token and no network access.

**Result**: install 1.7 s, demo 0.9 s, exit code 1 (credentials to rotate). The
report distinguishes the three cases the tool exists to tell apart — `api-server`
CONFIRMED because its workflow ran `npm ci` on the exposing commit, `docs-site`
LIKELY with a DEVELOPER-scope credential because its workflow installs nothing,
`web-frontend` absent because it skipped over the window — and the rotation list
names two credentials out of three in `api-server`, leaving out the one that
workflow never reads. The HTML report is 3.6 KB with zero external references.

**Change**: none needed; the run also fixed the demo's own gap — the first version
did not derive install evidence from the committed workflows, so every grade came
out LIKELY and the CONFIRMED/LIKELY distinction the demo exists to show was
invisible.

**Verification**: a CI job (`.github/workflows/demo.yml`) now runs the same path on
a clean runner and asserts the exit code and the three lines above, so the
evaluator path cannot rot without the build going red.

## E10 — Does the exit-code contract survive the process boundary?

**Assumption**: the four exit codes describe every outcome, so a CI gate can act
on them without reading the report.

**Method**: drive the CLI with a fake `gh` on `PATH` that truncates its listing
the way the real one does, with a stale cache whose fetch fails, with `gh` absent
entirely, and with a malformed advisory — checking the code and the machine-readable
report each time.

**Result**: three ways to report a clean that was never established.
`--limit` truncation dropped the unscanned repositories with no trace: three
infected repositories and three credentials collapsed into `rotate: nothing`,
exit 0, and an HTML artifact whose only verdict line was "No exposure found".
A failed `git fetch` on a cached clone was ignored, so an old clean history was
judged as current. And a missing `gh` escaped as a traceback with exit 1 — which
in this contract reads as "rotate these credentials".

**Changes**: a listing that reaches `--limit` is an error that forces exit 2; a
failed fetch is an error naming the stale cache; clones are keyed by
organization *and* name with the remote verified, so two organizations sharing a
repository name cannot be judged with each other's history; a missing tool exits
3; argparse usage errors exit 3 rather than colliding with "incomplete"; and
`--org` together with `--repo` is refused instead of silently ignoring the latter.

**Verification**: the truncated scan now reports `scan_complete: false`, exit 2,
and the reason in `errors`. A CI job asserts the three codes on every push.

## E11 — Does a default CI checkout read as clean?

**Assumption**: the CI job that judges this repository behaves like a developer's
clone, so the same command yields the same verdict.

**Method**: none planned — the demo workflow failed on its own assertion, which is
how the question got asked. The step expected exit 0 from scanning this repository
and got exit 1.

**Result**: correct behaviour, wrong expectation. `actions/checkout` clones at
depth 1 by default, so the walker found a truncated history, refused to call the
repository clean, and asked for a broad rotation — exactly the shallow-clone guard
working end to end. Locally the same scan exits 0 because the clone is complete.

**Changes**: the job that judges this repository now checks out with
`fetch-depth: 0`, and the workflow additionally creates a shallow clone on purpose
and asserts it exits 1 with both "shallow clone" and "cannot prove absence" in the
report. A unit test pins the same pair of outcomes.

**Verification**: the demo job passes with the deep checkout and fails if the
shallow assertion ever stops holding — the guard is now proven by CI rather than
asserted in a docstring.
