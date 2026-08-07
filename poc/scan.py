#!/usr/bin/env python3
"""deptrail PoC — cross-checks an IOC (compromised package@version + attack window)
against the git history of every lockfile in an organization's repos."""
import json, subprocess, sys
from datetime import datetime
from pathlib import Path

def sh(args, cwd):
    return subprocess.run(args, cwd=cwd, capture_output=True, text=True, check=True).stdout

def lockfile_history(repo):
    """Commits that touched the lockfile, as (time, hash) in ascending order."""
    out = sh(["git", "log", "--follow", "--format=%H|%cI", "--", "package-lock.json"], repo)
    hist = [(datetime.fromisoformat(t), h) for h, t in (line.split("|") for line in out.strip().splitlines())]
    return sorted(hist)

def lock_at(repo, commit):
    return json.loads(sh(["git", "show", f"{commit}:package-lock.json"], repo))

def version_of(lock, pkg):
    entry = lock.get("packages", {}).get(f"node_modules/{pkg}")
    return entry["version"] if entry else None

def transitive_path(lock, pkg):
    """Walk the lockfile graph backwards to find the root-to-pkg dependency path."""
    pkgs = lock.get("packages", {})
    parents = {}
    for path, entry in pkgs.items():
        name = path.rsplit("node_modules/", 1)[-1] if path else "(root)"
        for dep in entry.get("dependencies", {}):
            parents.setdefault(dep, name)
    chain, cur = [pkg], pkg
    while cur in parents and parents[cur] != "(root)":
        cur = parents[cur]
        chain.append(cur)
    return " → ".join(reversed(chain))

def scan_repo(repo, ioc):
    """A repo is exposed if any interval [commit time, next commit time) pinned a
    compromised version and that interval overlaps the attack window."""
    win_start, win_end = (datetime.fromisoformat(t) for t in ioc["window"])
    hist = lockfile_history(repo)
    findings = []
    for i, (t, commit) in enumerate(hist):
        lock = lock_at(repo, commit)
        ver = version_of(lock, ioc["package"])
        if ver not in ioc["malicious_versions"]:
            continue
        t_end = hist[i + 1][0] if i + 1 < len(hist) else datetime.now(t.tzinfo)
        if t <= win_end and t_end >= win_start:
            findings.append({"version": ver, "since": t, "until": t_end,
                            "commit": commit[:8], "path": transitive_path(lock, ioc["package"])})
    return findings

def main(org_dir, ioc_file):
    ioc = json.loads(Path(ioc_file).read_text())
    print(f"IOC: {ioc['package']} {ioc['malicious_versions']} | attack window: {ioc['window'][0]} ~ {ioc['window'][1]}\n")
    for repo in sorted(p for p in Path(org_dir).iterdir() if (p / ".git").exists()):
        findings = scan_repo(repo, ioc)
        if findings:
            for f in findings:
                print(f"[EXPOSED] {repo.name:12s}: {ioc['package']}@{f['version']} introduced {f['since']:%m/%d %H:%M} (commit {f['commit']}), held until {f['until']:%m/%d %H:%M} — overlaps attack window")
                print(f"          transitive path: {f['path']}")
                print(f"          action: rotate secrets present in CI/dev environments during this window")
        else:
            lock = lock_at(repo, lockfile_history(repo)[-1][1])
            reason = "never held a compromised version" if version_of(lock, ioc["package"]) else f"does not use {ioc['package']}"
            print(f"[CLEAN]   {repo.name:12s}: {reason}")

if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])
