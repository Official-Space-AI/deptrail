# DepTrail

> **Time-axis forensics for npm supply-chain incidents** — did we install it, did it actually run, and what must be rotated?

[![PyPI](https://img.shields.io/pypi/v/deptrail)](https://pypi.org/project/deptrail/)
[![Python](https://img.shields.io/pypi/pyversions/deptrail)](https://pypi.org/project/deptrail/)
[![License](https://img.shields.io/pypi/l/deptrail)](https://github.com/Official-Space-AI/deptrail/blob/main/LICENSE)

When a supply-chain attack hits npm (Shai-Hulud, chalk/debug, TanStack, Keyv, ...), every organization asks the same three questions the morning after the IOC drops:

1. Did any of our repos install the compromised version **during the attack window**?
2. Did it actually **run** — in a CI build — or did it just sit in a lockfile?
3. Which **secrets** were in scope at that time and must be rotated?

Current-state scanners answer a different question — "are we infected **now**?". DepTrail answers "**were we hit then, and what must be rotated?**" by walking the full git history of your lockfiles, correlating it with CI run records, and grading every repo with evidence:

**`CONFIRMED` / `LIKELY` / `POSSIBLE` / `NO EVIDENCE`**

## Try it in ten seconds

No token, no network, no waiting — the bundled demo builds a mock infection and
judges it with the production code path:

```bash
pip install deptrail          # Python 3.10+, no dependencies
deptrail demo                 # writes .deptrail-demo/ here; --workdir puts it elsewhere
```

```
built 4 synthetic demo repositories in .deptrail-demo (not a real incident)
advisory GHSA-demo-0000-0000 — Demo incident — chalk compromised
scanned 4 repo(s); worst grade CONFIRMED
installable windows (one per judgment)
  chalk@5.6.1: 2025-11-24T00:00:00+00:00 → 2025-11-26T23:59:59+00:00
    provenance: start operator-supplied from https://example.test/demo-advisory; end
        operator-supplied from https://example.test/demo-advisory

timeline
  [LIKELY     ] docs-site: chalk@5.6.1 in package-lock.json 2025-11-25 12:00 → still pinned
                run 4415 (Docs, push) built 62741f22 at 2025-11-25T13:00:00+00:00, while 5.6.1 was still served, but the workflows at that commit install no dependencies
  [CONFIRMED  ] api-server: chalk@5.6.1 in package-lock.json 2025-11-25 14:30 → 2025-11-28 09:00
                run 4412 (CI, push) built 54676c71 at 2025-11-25T15:30:00+00:00, while 5.6.1 was still served by the registry
                the workflows at that commit install dependencies, so 5.6.1 executed

rotate (3 credential(s))
  [CONFIRMED  ] api-server: DEPLOY_KEY (run 4412) — named in .github/workflows/ci.yml at
                54676c71 (covers chalk@5.6.1)
  [CONFIRMED  ] api-server: NPM_TOKEN (run 4412) — named in .github/workflows/ci.yml at 54676c71
                (covers chalk@5.6.1)
  [LIKELY     ] docs-site: ALGOLIA_KEY [DEVELOPER] — pinned in package-lock.json, and no
                implicated run could have installed it — so any install happened outside CI;
                Actions secrets are not automatically present on a developer machine, but the
                same values often are, so investigate that machine's credentials as well (covers
                chalk@5.6.1)

not judged (no lockfile this tool can read)
  mobile-app: yarn.lock: Yarn lockfiles are not parsed yet, so the versions this tree installed were not judged

this scan cannot prove absence of exposure
```

Four repositories, four different answers. `api-server` holds a third secret the CI
workflow never reads, so it is not on the list. `web-frontend` never held the
version while the registry served it, so it is absent from the report entirely.
`mobile-app` is locked with Yarn, which this version cannot parse — so it is named
as unread rather than cleared, and it raises no credentials, because nothing about
it suggests one.

Each line of the rotation list ends with the versions it `covers`, which is how one
credential stays one line: an advisory naming 180 packages — the September 2025
Shai-Hulud wave named roughly that many — would otherwise repeat the same entry 180
times, once per package.

Exit codes split verdicts from non-verdicts, so a caller knows whether to act, to
retry, or to fix something:

| code | meaning | what to do |
|---|---|---|
| `0` | absence of exposure was established | nothing |
| `1` | credentials to rotate | act on the list |
| `2` | looked, and could not prove absence | deepen the clone, or investigate by hand |
| `3` | the request was malformed | fix the arguments or the advisory |
| `4` | the tool could not run | retry; a tool or an API call failed |

## How it differs from existing tools

| Capability | Dependabot | worm-sign | **DepTrail** |
|---|:---:|:---:|:---:|
| Current lockfile malware check | ✅ | ✅ | byproduct |
| Heuristic / payload detection | ✖ | ✅ | ✖ (their domain) |
| Attack-window exposure from **lockfile git history** | ✖ | ✖ | ✅ core |
| **CI run correlation** ("did it actually execute?") | ✖ | ✖ | ✅ core |
| Org-wide incident timeline | current only | ✖ | ✅ |
| Secrets rotation scope & checklist | ✖ | ✖ | ✅ |
| Evidence grading | ✖ | ✖ | ✅ |

Upstream IOC feeds (OSV malicious-packages, vendor advisories, wormsign.io) are **inputs**, not competitors. They are not yet *readable* inputs: DepTrail accepts advisories in its own schema and rejects anything else outright, so its package and version list is yours to supply. An importer for those feeds is [#10](https://github.com/Official-Space-AI/deptrail/issues/10).

## Real use

On incident day, start from the advisory — it is the only thing you have to write.
If you already have the package and version list, do not transcribe the timestamps:

```bash
deptrail advisory derive \
  --package chalk@5.6.1 --package debug@4.4.2 --package ansi-styles@6.2.2 \
  --id GHSA-... \
  --name "September 2025 npm maintainer phishing" \
  --source https://github.com/advisories/GHSA-... \
  --output incident.json
```

Each window start is read from that package's registry publish time and cited by
URL; each end is left `null`, because no registry records a removal time. This is
the one command that touches the network, and it is not a scan — it writes a file
you then pass to `scan`, so a verdict never depends on a registry the incident may
itself have taken down.

Or write one by hand — the alternative to the above, not a step after it, when you
have no version list to derive from:

`--id` is the advisory's own id, never one you invent, and `--end-unknown` records
that no registry publishes a removal time — see below.

```bash
deptrail advisory init \
  --id GHSA-... \
  --name "chalk compromised" \
  --package chalk --version 5.6.1 \
  --start 2025-11-24T00:00:00+00:00 \
  --end-unknown \
  --source https://github.com/advisories/GHSA-... \
  --output incident.json

# Check it before a verdict depends on it.
deptrail advisory validate incident.json
```

`init` fills exactly what you give it and leaves the rest as `REPLACE-ME`, which the
loader rejects by name — an advisory with blanks must not validate, because a half-filled
one would produce a confident `CLEAN`. Nothing is derived: the identifier in particular is
asked for rather than invented, since there has been more than one `chalk` incident and
the report keys its verdict on that field.

`--end-unknown` writes `"end": null`, which is usually the truth — no registry records
when a version stopped being served, so the window's right edge is not a fact anyone
holds. Pass `--end` only for a removal time somebody actually recorded; the advisory's own
publication time is not it, and using that hides everyone who installed in the gap. And
`init` will not accept silence for either: leave both out and the blank stands, because a
forgotten flag must not become a window that never closes.

The template carries the definition of the window in the file itself, because that is the
field most easily transcribed wrong and getting it backwards makes every scan report
clean. Full format in [`docs/ioc-format.md`](https://github.com/Official-Space-AI/deptrail/blob/main/docs/ioc-format.md).

Then judge:

```bash
deptrail scan --ioc incident.json --org my-org          # clone and judge an org
deptrail scan --ioc incident.json --repo . --no-ci      # one local clone, no token
deptrail scan --ioc incident.json --org my-org --format html --output report.html
deptrail feeds                                          # bundled advisories
```

As a GitHub Action:

```yaml
- uses: actions/checkout@v4
- uses: Official-Space-AI/deptrail@v0.1.1
  with:
    ioc: advisories/shai-hulud.json
    report: deptrail-report.html
```

The action installs the version it is pinned to, so the ref you write is the code
that runs. It fails the job when credentials need rotating, and always fails when
the scan could not run at all — a green check must never mean "we could not look".

## How it decides

- [`docs/grading.md`](https://github.com/Official-Space-AI/deptrail/blob/main/docs/grading.md) — what each grade requires, and why
  `POSSIBLE` still means rotate
- [`docs/rotation.md`](https://github.com/Official-Space-AI/deptrail/blob/main/docs/rotation.md) — how the credential list is scoped
- [`docs/ioc-format.md`](https://github.com/Official-Space-AI/deptrail/blob/main/docs/ioc-format.md) — how to write an advisory feed, and
  what a window means

## Limitations

What the tool cannot do, it says out loud — a scan that could not look must never
read as a scan that found nothing.

- **npm and pnpm lockfiles.** `package-lock.json`, `npm-shrinkwrap.json` and
  `pnpm-lock.yaml` (every `lockfileVersion` pnpm has written) are parsed. A tree
  locked with Yarn, Bun or Deno is reported as **not judged**, exits `2`, and
  produces no rotation list — neither cleared nor accused
  ([#17](https://github.com/Official-Space-AI/deptrail/issues/17)).
- **A `package.json` with no lockfile is not yet reported.** Such a tree resolves
  ranges fresh at install time, so what it installed is unknown, but deciding
  *which* lockfile governed *which* directory *when* needs npm's workspace rules and
  is tracked separately ([#22](https://github.com/Official-Space-AI/deptrail/issues/22)).
- **An incomplete clone cannot be cleared.** Shallow (`actions/checkout` is depth-1 by
  default) and single-branch clones are detected, named, and reported as exit `2`. Use a
  full clone with `fetch-depth: 0`, or accept the gap deliberately with
  `--allow-incomplete-history` — off by default, and it still prints the reason. A
  partial clone (`--filter=blob:none`) is fine as long as its blobs can be fetched; any
  snapshot that could not be read is listed instead.
- **A one-branch `fetch` cannot be told from a full clone.** `git init` + `git fetch
  origin <branch>` keeps a wildcard refspec, so a branch that was never fetched looks
  like a branch that does not exist. Deciding this needs the remote's ref list
  ([#27](https://github.com/Official-Space-AI/deptrail/issues/27)).
- **A pull-request run installed a tree that is in no branch.** GitHub synthesises
  `refs/pull/N/merge` for `pull_request` events, and it is reachable from no ref in a
  normal clone, so what such a run installed is currently graded from the head commit
  instead ([#25](https://github.com/Official-Space-AI/deptrail/issues/25)).
- **Submodules are not crossed.** `git log` does not descend into a gitlink, so a
  Node project inside a submodule is invisible
  ([#21](https://github.com/Official-Space-AI/deptrail/issues/21)).
- **CI evidence is bounded by retention.** GitHub keeps run records for about 90
  days; older incidents can reach `LIKELY` but not `CONFIRMED`.
- **Secret values are never visible**, only names — so the report tells you what to
  rotate, not what leaked.
- **Advisories are an input, not a feature.** Two feeds ship with the package: a
  synthetic example for the demo, and the September 2025 incident above. Deriving a
  window from registry publish times is `deptrail advisory derive`; importing whole
  upstream feeds is still [#10](https://github.com/Official-Space-AI/deptrail/issues/10).

## Validated against a real incident

A bundled feed covers the September 2025 npm maintainer phishing — 20 packages,
from `chalk` 5.6.1 and `debug` 4.4.2 to `color` 5.0.1. Nothing in it was
transcribed. The names are OSV's contiguous malicious-package block
`MAL-2025-46966..46985`, every record published 2025-09-08 and bounded below by
RubyGems records from 2025-09-01 and above by unrelated npm records from 2025-09-09.
The malicious versions come from those records, and each window start is that
package's own publish time read from the registry.

```bash
deptrail scan --ioc npm-2025-09-08-chalk-debug --repo /path/to/clone
```

It has been run against a real affected repository and a real unaffected one, with
the ground truth established from the git history and the registry **before** the
tool was run. On the affected repository the tool reported eight compromised
packages pinned at `2025-09-08T14:31:48Z`; a hand count of that lockfile finds the
same eight. On the unaffected one — 2,175 commits, 193 touching the lockfile — it
found nothing, and the lockfile provably held the safe `debug` 4.4.1 at every commit
spanning that package's five-day window.

Three things this does **not** establish, in this section's own spirit:

- The feed stays `partial`, so a CLEAN result under it means "not found among these
  20". A contiguous id block is strong evidence of one incident and not proof of
  exhaustiveness — a first attempt at this feed stopped at 18 packages and missed
  two.
- The `CONFIRMED` path has never been exercised against a real incident's CI
  history ([#66](https://github.com/Official-Space-AI/deptrail/issues/66)): the
  affected repository's Actions runs aged out at 90 days, so every verdict in that
  run was `POSSIBLE`.
- Most npm projects have moved to lockfiles this version cannot parse
  ([#65](https://github.com/Official-Space-AI/deptrail/issues/65)); of twelve
  well-known ones, one still ships a `package-lock.json`.

## Status

🏗 Built for the **2026 Korea Open Source Developer Contest**, and under active
development. Released on PyPI as
[`deptrail`](https://pypi.org/project/deptrail/). `deptrail --version` names the
version that is installed, so an answer can be reproduced with
`pip install deptrail==<version>` — reports do not yet carry the version that
wrote them ([#53](https://github.com/Official-Space-AI/deptrail/issues/53)).

Releases are published straight from a tag by
[`release.yml`](https://github.com/Official-Space-AI/deptrail/blob/main/.github/workflows/release.yml) over OIDC trusted publishing —
no API token exists to leak, and every artifact carries a PEP 740 attestation
tying it to the commit and workflow that built it. Nothing is uploaded until the
build proves the wheel installs into an empty environment, opens every bundled
feed, and produces the demo's rotation list.

## 한국어 요약

npm 공급망 침해 사건(예: Shai-Hulud 웜)이 터진 다음 날 아침, 각 조직이 수작업으로 하던 조사 — "우리 레포가 공격 기간에 감염 버전을 설치했나 → 실제로 CI에서 실행됐나 → 어떤 시크릿을 재발급해야 하나" — 를 lockfile의 git 이력과 CI 실행 기록을 교차 대조해 **증거 등급**(확정/개연성 높음/가능성 있음/증거 없음)과 함께 자동 판정하는 도구입니다. "지금 감염돼 있나"를 보는 기존 스캐너(Dependabot, worm-sign)와 달리 **과거의 시간축**을 재구성합니다.

## License

[Apache-2.0](https://github.com/Official-Space-AI/deptrail/blob/main/LICENSE)
