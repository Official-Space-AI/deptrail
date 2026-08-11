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

## E12 — Does a repository shaped unlike our fixtures get a real answer?

**Assumption**: 235 passing tests and 93% line coverage mean the scanner's inputs
are covered, so the next class of defect will be in the judgment, not in what the
scanner accepts as input.

**Method**: build three throwaway repositories, each pinning `chalk@5.6.1` inside
the advisory window, differing only in which lockfile they use — `yarn.lock`,
`npm-shrinkwrap.json`, and none at all (a Python project) — and scan each one.

**Result**: two false cleans. The Yarn and shrinkwrap repositories both reported
`no exposure found`, `rotate: nothing`, and exit `0` — the code documented as
"absence was proven". The Python repository reported the same three things and was
right, and its output was byte-identical to the other two, so nothing in the report
distinguished "you are clear" from "we could not read your project".

The cause was one string: lockfile discovery matched the basename
`package-lock.json` exactly. `npm-shrinkwrap.json` is npm's own lockfile with the
same schema — feeding one straight to the parser returns the right version set, so
only discovery excluded it. Meanwhile `grading.INSTALL_COMMANDS` already recognised
`yarn install` and `pnpm install`, so on a Yarn repository the CI half of the tool
looked like it was working while the history half silently found nothing.

`grep -ric "yarn\|pnpm\|shrinkwrap" tests/*.py` returned 0. Every fixture in the
suite used `package-lock.json`, so the corpus encoded the same assumption as the
code. No number of passing tests could have found this, and neither of the two
independent reviews did: they read the code against its own premise.

**Changes**: `npm-shrinkwrap.json` became a first-class lockfile. A lockfile in a
dialect this version cannot parse, or a Node project with no readable lockfile, is
recorded as an *unread tree* — the repository is `INDETERMINATE`, the report lists
it under "not judged" with the filename, and the scan exits `2`. Unread trees
deliberately do not raise a grade or a credential: unlike a lost snapshot, nothing
was hidden from us, and grading them `POSSIBLE` would put every Yarn project's
whole secret store on a rotation list. Writing the org-level test then exposed a
second hole — a repository where one tree was read and exposed while another was
never legible carried an `EXPOSED` verdict and still claimed the scan was complete.
The demo gained a fourth repository locked with Yarn, so the evaluator sees this
answer in the first command they run.

**Verification**: the three repositories are pinned as end-to-end tests on their
exit codes (`2`, `1`, `0`), plus unit tests for each dialect, for a mixed
repository, and for a Yarn fixture under `tests/fixtures` that must *not* cost a
tooling project its all-clear. The demo workflow builds a Yarn project on the
runner and asserts exit 2 with an empty rotation list.

## E13 — Is "no lockfile we can read" a property of a repository?

**Assumption**: the E12 fix was complete. A repository either had a lockfile this
tool can read or it did not, so one question per repository was enough.

**Method**: both reviews of the E12 commit were told to build repositories rather
than read code, and to hunt in two directions at once — shapes that still get a
false clean, and honest shapes pushed to a false alarm. Nine such repositories were
built with real git history and scanned.

**Result**: the single per-repository question was wrong in both directions
simultaneously, which is why it looked right.

*Too permissive.* Any lockfile anywhere in history silenced the check, so exit 0
came back for: a `package-lock.json` deleted before the window with its
`package.json` still there — the tree ran unlocked exactly when the malicious
version was installable; a monorepo where one app was locked and the app beside it
was not; and a repository whose only lockfile was a test fixture, which cleared the
deployed root tree it says nothing about. A deployed application under `examples/`
was also filed away as sample data, even when a workflow named that directory as
its `working-directory` — the escape hatch that already existed for exposures had
not been extended to unread trees.

*Too strict.* Every foreign lockfile ever committed denied an all-clear forever, so
a project that migrated off Yarn years before the incident could never be cleared
again. `has_manifest` omitted the exact-basename check its sibling function
documents, so a single `metadata-package.json` in a Python repository produced exit
2; and because it returned a boolean rather than paths, a `tests/fixtures/package.json`
could not be set aside the way a fixture lockfile is.

Two further defects came from the same "per repository" habit elsewhere. An
exposure wins the aggregate verdict, and both the completeness claim and the
repo-wide rotation fallback were keyed on that verdict — so in a repository where
one tree was exposed and a second npm lockfile failed to parse, the report claimed
`scan_complete: true` and dropped every credential the narrow evidence did not
name. And adding `npm-shrinkwrap.json` support in E12 had created a false
*exposure*: npm ignores `package-lock.json` when a shrinkwrap sits beside it, so a
malicious pin in the file npm never read was reported as real.

**Changes**: lock coverage is now judged per path over the window. Existence
intervals are read from git — a file whose contents cannot be parsed still says
exactly when it was there — and a lockfile governs only its own directory and the
directories beneath it, which is how npm workspaces actually resolve. A
`package.json` no lockfile governed during the window becomes an unread tree
carrying its own path, so the fixture rule and the workflow-names-the-directory
rule both apply to it. Precedence is decided per commit. `proves_absence` and the
rotation fallback check lost evidence independently of the aggregate verdict.
`deno.lock` joined the table. The HTML banner no longer wears the all-clear colour
when the scan could not prove absence, and the Action annotates exit 2 as a warning
instead of passing silently.

**Verification**: the nine repositories are pinned as tests, each asserting the
exit code that was wrong before. Two properties are now tested in both directions,
which is what the round was really about: a lockfile must clear the tree it governs
and only that tree, and a foreign lockfile must count during the window and only
during the window.

## E14 — Is coverage a yes/no question?

**Assumption**: after E13, coverage was computed per path, which is the right
granularity. What remained were details.

**Method**: two more review rounds on the same branch, each told to build
repositories rather than read code, on both sides of the ledger; `npm install` run
locally against real workspace layouts to settle what a root lockfile covers; a
200-package monorepo timed against earlier commits; and a check of what
`git cat-file --batch-check -z` actually emits.

**Result**: the granularity was right and the *type* was wrong, twice over.

Round two: coverage had become a boolean — "did a lockfile overlap the window" —
where the honest answer is which parts of the window it covered. A lockfile removed
mid-window covered the whole of it. An interval was closed by the first descendant
deletion found on *any* ref, so a `main` that dropped a manifest before the incident
cleared a feature branch that still carried it — the cross-branch mistake E3 found
in exposure intervals, repeated in new code. Ancestor inheritance ignored npm's
workspace declaration, clearing standalone applications that had never been locked;
the test meant to cover this declared no workspaces, so it proved nothing. Precedence
was read from the wrong log: deleting an `npm-shrinkwrap.json` puts the
`package-lock.json` beside it back in charge without touching that file. And every
walker warning counted as lost evidence, so a rebase that rewrote a committer date
put a whole secret store on the rotation list.

Round three, on the fix for round two: spans still lose the lineage they came from.
Within one ref's reachable history, a lockfile that only ever existed on a side
branch covers `main`'s unlocked window on the time axis — a branch that added a lock
before the incident and merged after it cleared a `main` that was unlocked
throughout. Two more followed from the same loss: the workspace declaration was read
only at the commit that opened the lockfile's span, so dropping a member from
`workspaces` without touching the lockfile kept it "covered"; and the reported
witness was the manifest span's start rather than a commit inside the uncovered gap,
so the workflow-evidence check looked at the wrong tree. Four smaller defects came
with them: a span of zero length was discarded, so a file added at the window's
closing instant was ignored though the window is documented as inclusive; a
shrinkwrap appearing did not close an existing exposure, which then read as "still
pinned" about a file nothing installs; `-z` output was split on newlines as well as
NUL, turning `line\nbreak/package-lock.json` into a file called
`break/package-lock.json`; and the composite action never declared its `exit-code`
output, so the new job asserting it would have failed on a blank value.

The performance claim from round two was also wrong. `cat-file --batch-check -z`
takes NUL-delimited *input* and writes LF-delimited *output* — `-Z` is the one that
does both — so the batch never matched its own length check and fell back to one
call per pair.

**Changes**: the manifest-coverage feature was **removed from the branch** and given
its own issue (#22) with the npm measurements, the three failed designs, and the 13
scenarios as acceptance criteria. What ships is the part that survived three rounds
of attack: dialect recognition scoped to the window, lockfile precedence decided per
commit and closing an interval when it changes hands, the warnings/diagnostics split,
the inclusive window boundary, correct NUL parsing, and the action's declared output.

Judgment behind the split: every finding in rounds two and three was in the
manifest-coverage code, and each fix revealed the next because spans of presence are
the wrong abstraction for it — the next attempt needs state evaluated per commit,
which is a different design rather than another patch. Shipping the rest now leaves
that one case where it already was on `main`, unreported and documented, while the
false clean that started #16 — a Yarn or shrinkwrap repository reported clean — is
fixed.

**Verification**: the surviving behaviour is pinned by tests for the closing
instant, the shrinkwrap handover in both directions, the newline path, and the
foreign-lockfile window in all three positions (before, during, after). Removing the
coverage pass also removed its cost: the 200-package monorepo is back to 5.4 s
against a 5.1 s baseline, from 12 s.

## E15 — What does the prior art do about all this?

**Assumption**: after three rounds of review on the same sub-problem, the model was
being reinvented rather than borrowed. Someone must already have solved "which
lockfile governed which tree, when".

**Method**: a five-angle survey — production dependency tooling read as source, the
package managers' own libraries, the research literature, published incident practice,
and the general technique of modelling state over a git DAG — with each angle's
load-bearing claims re-checked against primary sources by a second reader. Two angles
were cut short by a session limit; the three that completed are the basis for what
follows, and the gaps are named at the end.

**Result, in the order it changes what we do.**

*A false clean in code that was already merged.* Git's default history simplification
follows only one parent of a merge that is TREESAME to it. So a branch that pinned the
malicious version and then **lost the merge conflict** disappears from
`git log <ref> -- package-lock.json` completely, and if the branch was deleted after
merging there is no ref left to walk either. Built that repository: the malicious blob
is reachable from the merge, a pull-request run would have installed it, and deptrail
returned exit 0. `--full-history` shows the commit; the default does not. This is the
E3 lesson — a merge hides the pin — in a form no amount of reasoning about intervals
would have caught, because the commit was never in the input. Fixed, with a test that
fails when the flag is removed. Cost on a 200-package monorepo: 5.4 s → 5.6 s.

*Nobody has solved the coverage question, and the reason is structural.* Every
production scanner analyses exactly one checkout, so it never asks "which lockfile
governed D at commit C" — only "which lockfile is next to D right now". Renovate's
association logic, the most mature in the field, returns *true for every path* as soon
as the `workspaces` array contains one negated pattern, so an undeclared sibling
inherits the root lockfile; Dependabot mishandles the same negation differently. Both
err toward **over-crediting** governance, which is the false-clean direction. Porting
either would have imported the bug we were trying to avoid. The literature avoids the
case by construction: the first systematic study of lockfiles detects them in the root
only and discards repositories with more than one, and the closest history-
reconstruction work walks the default branch and lists our lineage failure as a threat
to validity, mitigated by averaging over 33 000 projects — an escape hatch a
per-repository verdict does not have.

*npm's own algorithm is borrowable; its lockfile shortcut is not.* The survey's headline
claim — that a lockfile is self-describing about its governance, so
`mapWorkspaces.virtual({lockfile})` answers the question from one blob — was **refuted by
the check attached to it**, and the refutation is the more useful result.
`virtual` intersects the declaration and the member set *as of the lockfile's last
write*; governance at a commit is a function of that commit's root `package.json`. When
the two have drifted, a **narrowed** declaration leaves `virtual` still calling a
directory a member that npm now treats as undeclared — the false-clean direction. It is
also not a public API, and it returns an empty map with no error for lockfileVersion 1,
so it cannot distinguish "no workspaces" from "cannot tell".

What survives is worth more than what was claimed: the *authority* is the manifest at the
commit (npm's own installer uses the filesystem `mapWorkspaces({cwd, pkg})`, and only
`load-virtual` touches the virtual variant — to detect lockfile/manifest inconsistency,
not to establish governance); the lockfile's recorded declaration is a **staleness
detector**, which is what arborist's `flagsSuspect` uses it for; and the ordered-negation
pattern semantics can be taken from npm through the documented entry point rather than
rewritten. One production data point cuts the other way and is worth weighing: Dependabot
does **not** walk to parent directories for npm lockfiles at all, so the largest
deployment of this logic errs toward over-reporting rather than toward a false clean.
Recorded in #22, including the correction.

*The window we consume does not exist as data.* OSV and the GHSA malware records model
malice as a bare version list. The left edge is derivable — the registry keeps
`time[version]` after an unpublish — but **the right edge is recorded nowhere**, and it
is not even one interval per incident: for a range-resolving install the window closes
when the next satisfying good version is published, which differed from the unpublish
time by five days in a real case. Our schema's closed per-advisory window is therefore
wrong in shape. Filed as #23.

*Practice is much coarser than this tool, and that cuts both ways.* CISA prescribes
rotation unconditionally, in parallel with the dependency review rather than downstream
of it, so precise scoping buys nothing at the level of the decision that costs money.
What responders actually reconstruct is the (run, secret) join — "identified CI runs
affected, identified secrets available to those runs" — which is exactly what our
rotation list is, and is *not* a list of paths and intervals. Meanwhile the detector
script that responders actually ran classifies the no-lockfile case as LOW risk and
prints "Your current installation is safe" for it: the failure is a missing **tier**,
not a missing algorithm, which is a strong argument that refusing to credit what we
cannot read already beats what shipped, without #22 being finished.

**Changes**: `--full-history` on every path log, with the regression test. #22 rewritten
around npm's own resolver and a per-commit tree predicate. #23 opened for window
semantics. #20 given the exit-code precedent from Snyk and OSV-Scanner, which both
reserve a distinct code for "insufficient evidence" and refuse by default. #24 opened
for the npm cache index as dated install evidence. Regenerating a lockfile at analysis
time is now explicitly forbidden — the published move for a missing lockfile is
`npm i --package-lock-only`, which resolves against *today's* registry and would
manufacture a clean answer.

**Verification**: the merge-loss repository is a test that fails without the flag. The
prior-art claims behind each change above were re-checked against primary sources by a
second reader, and the two angles that did not complete — how other systems model state
over a DAG, and independent verification of the literature and incident claims — are
named as open in #22 rather than treated as settled.

### Status of the evidence in E15

Two of five angles did not complete, and the independent checks landed unevenly. The
record, so the reader can weight each claim:

- **Checked and held**: Renovate's negation over-match (with the refinement that it fires
  when the workspace root is the repository root), Dependabot's different mishandling of
  the same negation, and Dependabot's npm lockfile lookup being same-directory only.
- **Checked and refuted**: the lockfile-is-self-describing claim, corrected above.
- **Checked by me directly**: git's path-log simplification hiding a merge-losing branch
  (a test in this repository), and OSV-Scanner's documented exit codes.
- **Not yet independently checked**: every claim from the literature and
  incident-practice angles, including the ~26% no-lockfile base rate, the
  `npm i --package-lock-only` hazard, the community detector's "safe" output, and the npm
  cache index as a dated ledger. They are recorded in #22, #23 and #24 as the reasoning
  behind those issues, not as settled fact, and the verification is in flight.
- **Not surveyed at all**: how other systems model state over a git DAG at scale, which
  is the angle that would most directly inform #22's second step.

## E16 — Finishing the survey: what the last two angles and the critic found

**Assumption**: E15 recorded the three angles that completed. The remaining two — how
other systems model state over a git DAG, and independent verification of the literature
and incident claims — would refine the design but not change what ships.

**Method**: resumed the survey so the missing angle, the eight outstanding
verifications, the synthesis and a completeness critic all ran. Every claim the synthesis
made about *this* repository's code was then re-measured here before being acted on.

**Result: two more false cleans in shipped code, and a design conclusion that closes the
question of representation.**

*A lockfile introduced by a merge was never discovered at all.* `git log --name-only`
prints **nothing** for a merge commit unless `--diff-merges` is given, and it defaults to
off. Built a repository whose `yarn.lock` is present at HEAD, added by the merge commit
itself and in neither parent: discovery found zero paths and the scan returned exit 0.
This is worse than E15's case, where the file at least no longer existed — here the
unreadable lockfile is sitting in the current tree. `--diff-merges=first-parent` finds
it. The same command also needed `--no-renames`, because rename detection collapses
"`package-lock.json` deleted, `npm-shrinkwrap.json` added" into a single `R` record and
hides a precedence handover. Measured loss on real repositories, from the survey: two
paths on next.js, five on vscode, one of them a `yarn.lock` that would have forced
INDETERMINATE.

*Two kinds of truncated clone were silent.* Only shallow clones were detected. A
**partial** clone (`remote.origin.promisor=true`, filter `blob:none`) has the commits but
not the blobs; a **single-branch** clone has a refspec with no wildcard, which makes
"every ref testifies" false while nothing said so. Both verified against clones of this
repository, both now named in the report, and a full clone is still cleared — the control
matters, because every check of this kind can be satisfied by never clearing anything.

*Presence was being asked of the blob instead of the tree.* `cat-file -e <sha>:<path>`
needs the blob, so on a partial clone it either fetches from the promisor remote one
object at a time or answers "missing" for a file plainly in the tree. `ls-tree` answers
from local data; trees are never filtered out by `blob:none`.

*The representation question is settled, and not by preference.* Interval models
presuppose a single line of time evolution; branched evolution is a separate indexing
problem (Jiang, Salzberg, Lomet, Barrena, *The BT-tree: A Branched and Temporal Access
Method*, VLDB 2000), and interval temporal logics are defined over linearly ordered
domains, so "the interval during which F was present" is not well-formed over a DAG
until a lineage is chosen. Design #3 failed for a reason identified 26 years ago. The
established shape is per-commit state as the stored fact, with intervals **derived per
lineage at report time** — which is what LGTM/Semmle and Software Heritage both do. The
survey validated a fold, `state(C) = state(firstParent(C)) ⊕ delta(C vs first parent)`
over `--topo-order --reverse --all --diff-merges=first-parent`, against `git ls-tree` on
four real repositories: 2 336 sampled commits, 1 105 of them merges, zero mismatches,
and 0.76 s for npm/cli through 24.3 s for vscode's 184 000 commits.

*The workspace matcher can be ported rather than delegated, and now has an oracle.*
Delegation does not survive: `mapWorkspaces.virtual` is the retracted shortcut, the
documented `mapWorkspaces()` needs trees materialised to disk (~1.3 s per commit) plus a
Node runtime, and `@npmcli/config`'s `loadLocalPrefix()` never reads a lockfile and walks
past the checkout to the filesystem root. A 141-line stdlib-only Python port was written
and differentially tested against npm 10.9.3's own `@npmcli/map-workspaces`: 1 234 cases
across hand-written adversarial, random and path-derived suites, zero disagreements. The
fuzzer earned its place by finding a semantics no angle had reported — **positive
patterns skip dotfiles, negated ones do not**, because negations are handed to glob's
`ignore` list, which is always parsed `dot: true`. Three different dot policies inside one
function.

*And the sub-problem is narrower than we thought.* On npm/cli's own history, "a manifest
with no governing lockfile" fires roughly 366 times per commit, and every one is a test
fixture nobody installs. The predicate has to be **installable *and* unlocked**, which
means the existing `is_probably_installed` gate and the workflow-names-the-directory
escape hatch are load-bearing rather than polish. That measurement is n=1 and on the
least representative repository imaginable, so it is recorded as a reason to keep the
gate, not as a rate.

**Changes**: `--diff-merges=first-parent --no-renames` on discovery, `--no-renames` on
path logs, presence via `ls-tree`, and partial/single-branch clone detection — each with a
test that fails when the fix is removed, plus a full-clone control. #22 rewritten again
around per-commit state and the ported matcher.

**What the critic found that nobody looked at**, now recorded in the issues rather than
lost: Turborepo's `crates/turborepo-lockfiles` implements exactly this primitive per
ecosystem, with `Ok(None)` as a first-class "not governed" and a `global_change` guard for
lockfile-format changes — the closest prior art in existence, and no angle opened it. For
`pull_request` events, which were 62% of npm/cli's last hundred runs, the tree CI
installed is a GitHub-synthesised `refs/pull/N/merge` commit that is reachable from **no
branch** and absent from every clone, though it is fetchable on demand. The
`actions/setup-node` cache key is `(ref, lockfile content hash, timestamp)` published by
CI itself. And `overrides`/`resolutions`, pnpm `catalog:` ranges that live outside the
member manifest, and private-registry mirrors that served the malicious tarball after
npmjs.org removed it are all unmodelled.

**Verification**: 269 tests. Each of the three fixes above was mutation-checked — the
merge-discovery test and both truncation branches fail when their production line is
disabled. Every scenario from the four earlier review rounds still returns the exit code
it should, the demo still exits 1, and this repository still clears itself at exit 0.
