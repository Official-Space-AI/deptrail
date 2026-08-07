# DepTrail

> **Time-axis forensics for npm supply-chain incidents** — did we install it, did it actually run, and what must be rotated?

When a supply-chain attack hits npm (Shai-Hulud, chalk/debug, TanStack, Keyv, ...), every organization asks the same three questions the morning after the IOC drops:

1. Did any of our repos install the compromised version **during the attack window**?
2. Did it actually **run** — in a CI build — or did it just sit in a lockfile?
3. Which **secrets** were in scope at that time and must be rotated?

Current-state scanners answer a different question — "are we infected **now**?". DepTrail answers "**were we hit then, and what must be rotated?**" by walking the full git history of your lockfiles, correlating it with CI run records, and grading every repo with evidence:

**`CONFIRMED` / `LIKELY` / `POSSIBLE` / `NO EVIDENCE`**

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

## Status

🏗 Under active development for the **2026 Korea Open Source Developer Contest** (submission: Aug 27, 2026).

The core history-judgment engine is validated as a proof of concept — see [`poc/`](poc/), which reconstructs a mock infection against a synthetic three-repo org in ~3 seconds.

## 한국어 요약

npm 공급망 침해 사건(예: Shai-Hulud 웜)이 터진 다음 날 아침, 각 조직이 수작업으로 하던 조사 — "우리 레포가 공격 기간에 감염 버전을 설치했나 → 실제로 CI에서 실행됐나 → 어떤 시크릿을 재발급해야 하나" — 를 lockfile의 git 이력과 CI 실행 기록을 교차 대조해 **증거 등급(확정/개연성 높음/가능성 있음/증거 없음)**과 함께 자동 판정하는 도구입니다. "지금 감염돼 있나"를 보는 기존 스캐너(Dependabot, worm-sign)와 달리 **과거의 시간축**을 재구성합니다.

## License

[Apache-2.0](LICENSE)
