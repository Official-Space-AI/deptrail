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
deptrail demo
```

```
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

Each line ends with the versions it `covers`, and that is how one repository stays
one line: an advisory naming 180 packages — the September 2025 Shai-Hulud wave named
roughly that many — would otherwise print the same paragraph 180 times.

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
| Heuristic / payload detection | ✅ | ✅ | ✖ (their domain) |
| Attack-window exposure from **lockfile git history** | ✖ | ✖ | ✅ core |
| **CI run correlation** ("did it actually execute?") | ✖ | ✖ | ✅ core |
| Org-wide incident timeline | current only | ✖ | ✅ |
| Secrets rotation scope & checklist | ✖ | ✖ | ✅ |
| Evidence grading | ✖ | ✖ | ✅ |

Upstream IOC feeds (OSV malicious-packages, vendor advisories, wormsign.io) are **inputs**, not competitors — DepTrail consumes them.

## Real use

On incident day, start from the advisory — it is the only thing you have to write:

```bash
deptrail advisory init \
  --id GHSA-....                            # the advisory's own id, never guessed \
  --name "chalk compromised" \
  --package chalk --version 5.6.1 \
  --start 2025-11-24T00:00:00+00:00 \
  --end-unknown \
  --source https://github.com/advisories/GHSA-... \
  --output incident.json

deptrail advisory validate incident.json    # before a verdict depends on it
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

- **npm lockfiles only.** `package-lock.json` and `npm-shrinkwrap.json` are parsed.
  A tree locked with Yarn, pnpm, Bun or Deno is reported as **not judged**, exits
  `2`, and produces no rotation list — neither cleared nor accused
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
- **Advisories are an input, not a feature.** One example feed ships with the
  package; an importer that derives windows from registry publish times is
  [#10](https://github.com/Official-Space-AI/deptrail/issues/10).

## Status

🏗 Built for the **2026 Korea Open Source Developer Contest** (submitted Aug 27,
2026), and still under active development. Released on PyPI as
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
