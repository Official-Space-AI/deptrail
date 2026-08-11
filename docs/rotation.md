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

**Evidence about a lockfile we do track was lost** — a shallow clone (including
the default `actions/checkout`, which fetches depth 1), an unreadable snapshot, a
lockfile that failed to parse. A pin may be hidden in the part we could not see,
so the repository is graded `POSSIBLE`, every credential it can reach goes on the
list with the reason, and the run exits `1`. In CI, check out with `fetch-depth: 0`;
the bundled Action deepens the history itself.

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

## What the report refuses to claim

A report says it **cannot prove absence** whenever a repository failed to scan, a
tree could not be read, or the advisory declares partial coverage. In each case
something was not looked at, and "nothing found" would be the wrong sentence to
hand a responder.
