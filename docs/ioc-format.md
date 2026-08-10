# Advisory (IOC) format

An advisory is the question DepTrail answers: *which package versions were malicious, and during what window?* On incident day it is transcribed from a vendor blog post or GHSA entry — the format is deliberately small enough to write by hand in minutes.

```json
{
  "schema_version": 1,
  "id": "GHSA-0000-0000-0000",
  "name": "EXAMPLE — replace every value below",
  "ecosystem": "npm",
  "coverage": "partial",
  "window": {
    "start": "2026-01-02T19:20:42+00:00",
    "end": "2026-01-03T04:10:00+00:00"
  },
  "packages": [
    {
      "name": "example-package",
      "versions": ["1.2.3", "1.2.4"],
      "sources": ["https://example.test/advisory"],
      "notes": "start = publish time of 1.2.3; end = when the registry no longer served either version (verified, see notes)."
    }
  ],
  "sources": ["https://example.test/advisory"]
}
```

The window above is a **placeholder with the right shape**: start at the first
malicious publish, end after the artifact stopped being installable. Do not copy
timestamps from an advisory's headline — read the next section first.

## Fields

| Field | Required | Meaning |
|---|:---:|---|
| `schema_version` | ✅ | Must be `1`. Bumped only on a breaking change. |
| `id` | ✅ | Stable identifier — prefer the GHSA/CVE id, else a vendor tracking id. |
| `name` | ✅ | Human-readable incident name, shown in reports. |
| `ecosystem` | ✅ | `npm` (the only value the MVP judges). |
| `coverage` | ✅ | `complete` or `partial` — see below. |
| `window.start` / `.end` | ✅ | Interval in which the malicious artifact was **installable** (first malicious publish → registry removal), **inclusive on both ends**. See below — this is not the vendor's "attacker activity" window. |
| `packages[]` | ✅ | At least one compromised package. |
| `packages[].name` | ✅ | Exact npm name, scope included. |
| `packages[].versions[]` | ✅ | **Exact** versions. No ranges — a range would judge versions the advisory never named. |
| `packages[].window` | — | Overrides the advisory window for that package (waves publish at different times). |
| `packages[].sources[]` | ✅ | Where this entry came from. Provenance is not optional: a wrong IOC produces a wrong verdict. |
| `notes` (advisory or package) | — | Free text carried into reports. |

## The window is when the artifact was installable

This is the field most easily transcribed wrong, and getting it wrong produces a
feed that can only ever answer CLEAN.

Vendors publish the window in which the *attacker* was active. Victims are
exposed in a different window: from the moment the poisoned version appeared on
the registry until npm removed it. In the TanStack wave those differ by hours —
the CI compromise ran 11:29–19:15 UTC, while the malicious versions were
published from 19:20 UTC onward. A feed built from 11:29–19:15 closes *before*
any repo could install the bad artifact, so every scan returns CLEAN.

- **Start**: the publish time of the earliest malicious version (npm's registry
  `time` map gives this per version).
- **End**: a time you can state the artifact was **no longer installable**. The
  advisory's publication time is not that time — advisories are published while
  the bad versions are still up, and an end bound set there hides everyone who
  installed in the gap. Use whichever you can establish:
  1. a removal time the registry or advisory states, or
  2. the moment you personally checked and found the versions gone (`npm view
     <pkg> versions` no longer lists them) — record that check in `notes`, or
  3. failing both, the time you are writing the feed, which is by construction
     after the removal you already know happened.

  A wide window over-reports exposure; a narrow one hides it. Only one of those
  two errors is recoverable by a human reading the report.
- A package-level `window` must sit **inside** the advisory window; it narrows,
  never extends (extending is a transcription error, and the loader rejects it).

## Two rules that shape the format

**Nothing is inferred.** Unknown fields are an error, not a shrug — a typo'd key
in a feed transcribed at 3 a.m. would otherwise silently scan for the wrong
thing. Bounds must be full timestamps with a UTC offset: a bare `2025-11-24` is
rejected, because deciding which instants a published date covers is a judgment,
and it belongs in the feed where a reader of the report can see it (write
`2025-11-24T00:00:00+00:00` and `2025-11-24T23:59:59+00:00` yourself).

**Coverage is part of the evidence.** Advisories grow for days after an
incident. A `partial` feed can prove exposure but never its absence, so
`Advisory.coverage_warning` carries that caveat into the report — a CLEAN result
under a partial feed means "nothing found among the packages this feed lists".

## Bundled feeds

`deptrail` ships feeds under `src/deptrail/feeds/`, loadable by name:

```python
from deptrail.ioc import load_advisory
advisory = load_advisory("example-demo")        # bundled feed name, or any file path
queries = advisory.queries()                   # one WindowQuery per package
```

| Feed | Incident | Coverage |
|---|---|---|
| `example-demo` | Synthetic fixture matching `poc/make_demo_org.sh` | complete (not a real incident) |

**No real-incident feed ships yet, on purpose.** A first attempt at one
(TanStack / CVE-2026-45321) took its window from the vendor's attacker-activity
times and therefore could only return CLEAN — the exact failure this document now
warns about. Real feeds need per-version publish and removal times, which belong
to an importer reading the registry and OSV rather than to hand-copying; that
importer is tracked as its own work. Until it lands, write the feed for the
incident you are responding to from the guidance above, and treat a CLEAN verdict
under a `partial` feed as "not found among the packages this feed lists".

## Writing a feed on incident day

1. Copy the block at the top of this page.
2. Set `id`, `name`, and the `window` — the **installable** interval, not the attacker-activity times the advisory leads with (see above).
3. For each named package, add `name`, exact `versions`, and the URL you read it from.
4. Leave `coverage` as `partial` until you have the vendor's final list.
5. Run it — a malformed feed fails immediately with the offending field path.
