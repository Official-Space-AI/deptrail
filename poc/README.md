# PoC — validating the time-axis judgment core (2026-08-07)

Before starting the project proper, this 80-line script validated the core idea:
walking the git history of a lockfile and cross-checking it against an IOC attack
window is sufficient to judge past exposure.

## Reproduce

```bash
bash poc/make_demo_org.sh                        # build the mock org (3 repos)
python3 poc/scan.py poc/demo-org poc/ioc-demo.json
```

## Expected output

```
IOC: chalk ['5.6.1'] | attack window: 2025-11-24T00:00:00+09:00 ~ 2025-11-26T23:59:59+09:00

[EXPOSED] api-server  : chalk@5.6.1 introduced 11/25 14:30 (commit ...), held until 11/28 09:00 — overlaps attack window
          transitive path: express → debug → chalk
          action: rotate secrets present in CI/dev environments during this window
[CLEAN]   mobile-app  : does not use chalk
[CLEAN]   web-frontend: never held a compromised version
```

Runs in ~3 seconds for 3 repos. The production implementation (`src/deptrail`)
extends this with CI-run correlation and four-tier evidence grading
(CONFIRMED / LIKELY / POSSIBLE / NO EVIDENCE).
