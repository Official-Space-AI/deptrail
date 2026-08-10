# Evidence grading

A lockfile pinning a compromised version proves the pin, not the install. The
question a responder actually has to answer is narrower — *did an install run
while the malicious artifact was live, and therefore must these secrets be
rotated?* — so every exposure carries a grade and the facts the grade rests on.

| Grade | What it means | What the evidence looks like |
|---|---|---|
| `CONFIRMED` | An install ran against a lockfile pinning the malicious version | A CI run checked out the exposing commit and started while the artifact was both pinned and live |
| `LIKELY` | CI activity coincides with the exposure, but not provably with the install | A run on the exposing commit that started after removal, or runs in the window on other commits |
| `POSSIBLE` | The pin overlapped the window and nothing rules an install in or out | No run coincides, or run records for that period no longer exist |
| `NO_EVIDENCE` | No exposure interval overlapped the window | The lockfile never held a named version while it was live |

## Why POSSIBLE still means rotate

`POSSIBLE` is not a softer `CLEAN`. Two facts keep it on the rotation list:

- **Developer machines leave no records.** Whoever committed the lockfile ran the
  install locally, on a machine with credentials, and no CI history will ever
  show it.
- **Run records expire.** GitHub keeps them about 90 days by default, so a window
  from last winter has no run history left to consult. Absence of a run is not
  absence of an install, and the grader says so in a warning rather than letting
  the silence read as safety.

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
  an overlapping exposure to `NO_EVIDENCE`; only the absence of an overlap does.
