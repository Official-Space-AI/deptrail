# Advisory (IOC) format

An advisory is the question DepTrail answers: *which package versions were malicious, and during what window?* On incident day it is transcribed from a vendor blog post or GHSA entry — the format is deliberately small enough to write by hand in minutes.

```json
{
  "schema_version": 1,
  "id": "GHSA-g7cv-rxg3-hmpx",
  "name": "TanStack npm supply-chain compromise",
  "ecosystem": "npm",
  "coverage": "partial",
  "window": { "start": "2026-05-11T11:29:00+00:00", "end": "2026-05-11T19:15:00+00:00" },
  "packages": [
    {
      "name": "@mistralai/mistralai",
      "versions": ["2.2.2", "2.2.3", "2.2.4"],
      "sources": ["https://nvd.nist.gov/vuln/detail/CVE-2026-45321"],
      "notes": "Secondary victim package."
    }
  ],
  "sources": ["https://github.com/advisories/GHSA-g7cv-rxg3-hmpx"]
}
```

## Fields

| Field | Required | Meaning |
|---|:---:|---|
| `schema_version` | ✅ | Must be `1`. Bumped only on a breaking change. |
| `id` | ✅ | Stable identifier — prefer the GHSA/CVE id, else a vendor tracking id. |
| `name` | ✅ | Human-readable incident name, shown in reports. |
| `ecosystem` | ✅ | `npm` (the only value the MVP judges). |
| `coverage` | ✅ | `complete` or `partial` — see below. |
| `window.start` / `.end` | ✅ | Attack window, **inclusive on both ends**. |
| `packages[]` | ✅ | At least one compromised package. |
| `packages[].name` | ✅ | Exact npm name, scope included. |
| `packages[].versions[]` | ✅ | **Exact** versions. No ranges — a range would judge versions the advisory never named. |
| `packages[].window` | — | Overrides the advisory window for that package (waves publish at different times). |
| `packages[].sources[]` | ✅ | Where this entry came from. Provenance is not optional: a wrong IOC produces a wrong verdict. |
| `notes` (advisory or package) | — | Free text carried into reports. |

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
advisory = load_advisory("tanstack-2026-05")   # bundled name, or any file path
queries = advisory.queries()                   # one WindowQuery per package
```

| Feed | Incident | Coverage |
|---|---|---|
| `example-demo` | Synthetic fixture matching `poc/make_demo_org.sh` | complete (not a real incident) |
| `tanstack-2026-05` | TanStack / Shai-Hulud wave 4, CVE-2026-45321 | **partial excerpt** |

Bundled real-incident feeds are excerpts limited to entries verified against a
primary source. Transcribing full package lists (the TanStack wave alone touched
42 primary and 170+ secondary packages) belongs to an authoritative importer
rather than hand-copying — tracked separately. Until then, treat a CLEAN verdict
under a partial feed as "not found in this excerpt".

## Writing a feed on incident day

1. Copy the block at the top of this page.
2. Set `id`, `name`, and the `window` from the advisory's stated attacker activity times (keep the offset the vendor used).
3. For each named package, add `name`, exact `versions`, and the URL you read it from.
4. Leave `coverage` as `partial` until you have the vendor's final list.
5. Run it — a malformed feed fails immediately with the offending field path.
