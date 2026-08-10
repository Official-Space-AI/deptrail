# Evidence grading

A lockfile pinning a compromised version proves the pin, not the install. The
question a responder actually has to answer is narrower — *did an install run
while the malicious artifact was live, and therefore must these secrets be
rotated?* — so every exposure carries a grade and the facts the grade rests on.

| Grade | What it means | What the evidence looks like |
|---|---|---|
| `CONFIRMED` | An install ran against a lockfile pinning the malicious version | A CI run checked out the exposing commit, started while the artifact was pinned **and** live, and is shown to install dependencies |
| `LIKELY` | CI activity coincides with the exposure, but the install is not proven | A run on the exposing commit whose steps we could not inspect (or that installs nothing), a run on that commit after the artifact was pulled, or runs in the window on other commits |
| `POSSIBLE` | The pin overlapped the window and nothing rules an install in or out | No run coincides, records for that period no longer exist, or **the repository's history could not be read at all** |
| `NO_EVIDENCE` | No exposure interval overlapped the window, and the history was readable | The lockfile never held a named version while it was live |

`CONFIRMED` needs positive evidence on both axes — the run installed
dependencies, and it ran while the artifact was live. A run that predates the
version turning malicious fetched the clean artifact and is not evidence at all,
so it does not raise the grade.

## Why POSSIBLE still means rotate

`POSSIBLE` is not a softer `CLEAN`. Two facts keep it on the rotation list:

- **Developer machines leave no records.** Whoever committed the lockfile ran the
  install locally, on a machine with credentials, and no CI history will ever
  show it.
- **Run records expire.** GitHub keeps them about 90 days by default, so a window
  from last winter has no run history left to consult. Absence of a run is not
  absence of an install, and the grader says so in a warning rather than letting
  the silence read as safety.
- **An unreadable history clears nothing.** A shallow clone or an unreadable
  snapshot makes the walker return INDETERMINATE; the grade then becomes
  `POSSIBLE`, never `NO_EVIDENCE`. Clone depth must not decide whether a
  credential gets rotated.

The asymmetry is deliberate: rotating one credential that did not need it costs
minutes, while leaving one live in an attacker's hands is the incident repeating.

## What the grader deliberately does not do

- **No log reading.** Only run metadata (commit, start time, workflow) is used.
  Logs expire long before the runs they belong to, and metadata is enough to
  place an install in time.
- **No inference from a green build.** A successful run does not mean the install
  succeeded against the malicious version, and a failed one does not mean it
  never executed — install scripts run before most failures.
- **No clearing a repo from CI evidence alone.** Nothing in this module can move
  an overlapping exposure to `NO_EVIDENCE`; only the absence of an overlap in a
  history we could actually read does.
- **No trusting a rewritten timestamp.** Re-runs rewrite `startedAt`, so a run's
  effective time is the earlier of `createdAt`/`startedAt`.
- **No claiming a retention horizon.** GitHub does not publish per-repo
  retention, so a full page of results claims no horizon; an older window is
  reported as unanswered rather than quiet.

## What a `pull_request` run can and cannot show

For `pull_request` events GitHub checks out an ephemeral merge of the head and
base branches. The run's `headSha` is the branch commit — which is why matching
by SHA works — but what it installed is that merge, not the head snapshot alone.
A `CONFIRMED` grade resting on a PR run therefore proves an install of the merged
tree; where the distinction matters, the report cites the run id so a responder
can look.
