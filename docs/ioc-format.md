# Advisory (IOC) format

> **Start here:** `deptrail advisory init` writes a file to fill in and
> `deptrail advisory validate <file>` checks it before a verdict depends on it. Anything
> left blank fails validation on purpose — an advisory with holes must not be able to
> produce a confident `CLEAN`.

An advisory is the question DepTrail answers: *which package versions were malicious, and during what window?* On incident day it is transcribed from a vendor blog post or GHSA entry — the format is deliberately small enough to write by hand in minutes.

```json
{
  "schema_version": 2,
  "id": "GHSA-0000-0000-0000",
  "name": "EXAMPLE — replace every value below",
  "ecosystem": "npm",
  "coverage": "partial",
  "window": {
    "start": "2026-01-02T19:20:42+00:00",
    "end": null,
    "provenance": {
      "start": {
        "kind": "derived",
        "source": "https://registry.npmjs.org/example-package"
      },
      "end": {
        "kind": "unknown",
        "source": "https://registry.npmjs.org/example-package"
      }
    }
  },
  "packages": [
    {
      "name": "example-package",
      "versions": ["1.2.3", "1.2.4"],
      "sources": ["https://example.test/advisory"],
      "notes": "start = time['1.2.3'] from the registry packument. end = null: no registry records when a version stopped being served, so it is not known to have closed."
    }
  ],
  "sources": [
    "https://example.test/advisory",
    "https://registry.npmjs.org/example-package"
  ]
}
```

The window above is a **placeholder with the right shape**: start at the first
malicious publish, read from the registry; end `null`, because no registry records a
removal. Do not copy timestamps from an advisory's headline — read the next section
first.

## Fields

| Field | Required | Meaning |
|---|:---:|---|
| `schema_version` | ✅ | Must be `2`. Bumped only on a breaking change. |
| `id` | ✅ | Stable identifier — prefer the GHSA/CVE id, else a vendor tracking id. |
| `name` | ✅ | Human-readable incident name, shown in reports. |
| `ecosystem` | ✅ | `npm` (the only value the MVP judges). |
| `coverage` | ✅ | `complete` or `partial` — see below. |
| `window.start` / `.end` | ✅ | Interval in which the malicious artifact was **installable** (first malicious publish → registry removal), **inclusive on both ends**. `end` may be `null`, meaning "not known to have closed" — usually the honest answer, since no registry records a removal. See below; this is not the vendor's "attacker activity" window. |
| `window.provenance.start` / `.end` | ✅ | Each has a `kind` and exact `source` URL. Start is `operator-supplied` or `derived`; end is `operator-supplied`, `derived`, or `unknown`. `unknown` is required exactly when `end` is `null`. Reports repeat these values for every package judgment. |
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

**The start is a recorded fact. The end is not, and the format says so.**

- **Start**: the publish time of the malicious version, which npm's registry keeps
  per version in the packument's `time` map. It survives the version being
  unpublished — measured against `registry.npmjs.org` on 2026-08-13:

  | package | `time[version]` | still in `versions`? |
  |---|---|---|
  | `chalk` 5.6.1 | 2025-09-08T13:13:05.239Z | no |
  | `debug` 4.4.2 | 2025-09-08T13:12:39.973Z | no |
  | `ansi-styles` 6.2.2 | 2025-09-08T13:12:10.343Z | no |

  So you never have to guess the start: read it.

- **End**: write `null`, unless you have a removal time somebody actually recorded.
  `null` means *not known to have stopped being installable*, and it is the ordinary
  case — **no registry records a removal**. The packument gains no `unpublished` key
  and no timestamp; the version simply vanishes from `versions` while its `time`
  entry stays. There is nothing to read.

  The number nearest to hand is the advisory's publication time, and that is the one
  reliably wrong answer: advisories go out while the bad versions are still up, so an
  end set there hides everyone who installed in the gap.

  The next-good-version publish time is *not* the end either, and it is not even
  consistent between packages of one incident. From the same compromise:

  | package | malicious publish | next good version | gap |
  |---|---|---|---|
  | `chalk` 5.6.1 | 13:13:05 | 5.6.2 at 14:47:54 | 1h 34m |
  | `ansi-styles` 6.2.2 | 13:12:10 | 6.2.3 at 14:52:15 | 1h 40m |
  | `debug` 4.4.2 | 13:12:39 | 4.4.3 on **2025-09-13** | **5 days** |

  What an open end costs you: exposure is reported for any lockfile that pinned the
  version at any time after the start, including one committed long after the
  registry stopped serving it. What a guessed end costs you: a repository that was
  exposed is reported clean. A wide window over-reports; a narrow one hides. Only one
  of those two errors is recoverable by a human reading the report.

  `end` must still be **present**. Write `"end": null` — an omitted key reads the same
  as a mistyped one, and this format infers nothing.

- A package-level `window` must sit **inside** the advisory window; it narrows,
  never extends (extending is a transcription error, and the loader rejects it). An
  open end is the latest end there is, so an open package window fits only inside an
  open advisory window.

## Two rules that shape the format

**Nothing is inferred.** Unknown fields are an error, not a shrug — a typo'd key
in a feed transcribed at 3 a.m. would otherwise silently scan for the wrong
thing. `window.end` may be `null` and nothing else may be omitted; every bound that is
written must be a full timestamp with a UTC offset, so a bare `2025-11-24` is
rejected, because deciding which instants a published date covers is a judgment,
and it belongs in the feed where a reader of the report can see it (write
`2025-11-24T00:00:00+00:00` and `2025-11-24T23:59:59+00:00` yourself).

**Coverage is part of the evidence.** Advisories grow for days after an
incident. A `partial` feed can prove exposure but never its absence, so
`Advisory.coverage_warning` carries that caveat into the report — a CLEAN result
under a partial feed means "nothing found among the packages this feed lists".

**Window provenance is part of every judgment.** A timestamp copied by an operator and
one derived by an importer may have the same value but not the same evidentiary weight.
The report therefore names, for each package, how both bounds entered the snapshot and
the exact URL used. A package-level window carries its own provenance; a package without
one inherits the advisory window and its provenance.

## Bundled feeds

`deptrail` ships feeds under `src/deptrail/feeds/`, loadable by name:

```python
from deptrail.ioc import load_advisory
advisory = load_advisory("example-demo")        # bundled feed name, or any file path
queries = advisory.plan().queries              # one WindowQuery per package
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

If you have the package and version list, do not transcribe the timestamps —
`deptrail advisory derive` reads them out of the registry for you:

```bash
deptrail advisory derive \
  --package chalk@5.6.1 \
  --package debug@4.4.2 \
  --package ansi-styles@6.2.2 \
  --id GHSA-... \
  --name "September 2025 npm maintainer phishing" \
  --source https://github.com/advisories/GHSA-... \
  --output incident.json
```

For a wave naming many packages, put one `name@version` per line in a file and
pass `--packages-from`; `#` starts a comment.

Every `window.start` it writes is a `time[version]` entry read from that package's
packument, cited by URL and marked `derived`. Every `end` is `null` and marked
`unknown`, because no registry records a removal time. Versions of one package
published at different instants become separate waves, which is what the September
2025 compromise actually looks like: `ansi-styles` 6.2.2 at 13:12:10, `debug` 4.4.2
at 13:12:39, `chalk` 5.6.1 at 13:13:05.

A version the registry has no publish time for stops the import rather than being
skipped. A malicious version silently missing from a feed is the difference between
a repository being reported and being cleared.

**This is the only command that touches the network, and it is not a scan.** It
writes a file you read and then pass to `scan`. A verdict must not depend on a
registry the incident may itself have taken down, and a window that differs between
two runs of the same scan is not evidence.

### By hand

1. Copy the block at the top of this page.
2. Set `id`, `name`, and the `window`. Read the start from `https://registry.npmjs.org/<package>` → `time[<version>]`; leave `end` as `null` unless somebody recorded a removal. Record `derived` plus the packument URL for that start, and `unknown` plus the source you checked for the open end. Do not use the attacker-activity times the advisory leads with (see above).
3. For each named package, add `name`, exact `versions`, and the URL you read it from.
4. Leave `coverage` as `partial` until you have the vendor's final list.
5. Run it — a malformed feed fails immediately with the offending field path.
