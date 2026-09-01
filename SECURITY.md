# Security Policy

DepTrail is an incident-response tool. It reads repositories that may be
compromised, it makes network requests, and it can carry the operator's GitHub
token. This file says what it promises about that, and how to tell us when a
promise does not hold.

## Reporting a vulnerability

**Please do not open a public issue for a security report.**

Use GitHub's private vulnerability reporting on this repository:
**Security → Report a vulnerability**
([`/security/advisories/new`](https://github.com/Official-Space-AI/deptrail/security/advisories/new)).
It is private to the maintainers until an advisory is published, and it gives you a
place to discuss a fix before it exists.

Please include what you ran, what you saw, and — if you can — the smallest
repository or advisory file that reproduces it. A scratch fixture is worth more
than a description.

We will acknowledge a report within **5 working days** and tell you whether we
think it is a vulnerability, a defect, or working as intended. This is a small
project; if you have not heard back in that time, please assume the message went
astray rather than that it was ignored, and ping the thread.

## What counts as a vulnerability here

Because of what this tool does, two classes matter more than crashes.

### 1. A false all-clear

Exit code `0` means *absence of exposure was established*. Any input where the
tool exits 0 while history it could not examine exists is a security defect, not a
cosmetic one — a responder reads 0 and stops looking. Reports of this kind are
very welcome, and the wrong-verdict issue template exists for the non-security
version of the same thing.

### 2. A credential going somewhere it should not

The scan may carry a GitHub token. It promises the following, and each is a
vulnerability if you can break it:

- **A credential goes only to an address the operator named** — `--org`, or one
  `--repo` with `--slug`. An address read out of the repository under
  investigation never receives one.
- **Only over `https`, only to `github.com`**, and it does not follow a redirect to
  another host.
- **The query never reads the scanned repository's git configuration**, nor the
  operator's global or system config, nor configuration injected through the
  environment.
- **Nothing can ask the probe for a credential.** No credential helper runs; the
  only credential it holds is the header it was handed.
- **Certificate verification cannot be turned off** from the environment the scan
  inherits.
- **The token is not written to a command line**, where `ps` would show it.

Known and deliberate limits, which are therefore *not* vulnerabilities:

- The ssh client reads `~/.ssh` from the **account**, not from `HOME`, so an ssh
  remote in a scanned checkout is contacted with the operator's own key. OpenSSH
  ignores a redirected `HOME`; we cannot close this from here.
- `GIT_SSL_CAINFO` and the proxy environment variables are deliberately passed
  through: they are the only way a scan works on a network behind an intercepting
  proxy, and naming a CA still verifies against it.
- The scan makes network requests. It is not, and has never claimed to be, an
  offline tool.

### Out of scope

- Findings that require the attacker to already have write access to the
  operator's own `$HOME`, environment, or `$GIT_DIR` **and** whose consequence is
  limited to a misleading report. We treat those as defects and fix them, but they
  are not advisories.
- Reports about a repository this tool scans being malicious. That is the premise,
  not a bug.
- Denial of service by way of a repository that is simply very large.

## Supported versions

Pre-1.0. Fixes go to `main` and the next release from it; there is no maintained
branch of an older line. If you are running a released version, the answer to
"which version is patched" is "the next one after the report", and the advisory
will say so explicitly.

## Disclosure

We will credit you in the advisory unless you prefer otherwise, and we will agree a
disclosure date with you rather than announce one. If a report turns out to affect
another project as well, we would rather coordinate with them than publish first.
