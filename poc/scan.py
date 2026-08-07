#!/usr/bin/env python3
"""supplyscan PoC — IOC(감염 패키지@버전 + 공격 기간)를 조직 레포들의 lockfile git 이력과 대조한다."""
import json, subprocess, sys
from datetime import datetime
from pathlib import Path

def sh(args, cwd):
    return subprocess.run(args, cwd=cwd, capture_output=True, text=True, check=True).stdout

def lockfile_history(repo):
    """lockfile을 건드린 커밋들을 (시각, 해시) 오름차순으로 반환한다."""
    out = sh(["git", "log", "--follow", "--format=%H|%cI", "--", "package-lock.json"], repo)
    hist = [(datetime.fromisoformat(t), h) for h, t in (line.split("|") for line in out.strip().splitlines())]
    return sorted(hist)

def lock_at(repo, commit):
    return json.loads(sh(["git", "show", f"{commit}:package-lock.json"], repo))

def version_of(lock, pkg):
    entry = lock.get("packages", {}).get(f"node_modules/{pkg}")
    return entry["version"] if entry else None

def transitive_path(lock, pkg):
    """루트에서 pkg까지의 의존 경로를 lockfile 그래프를 거꾸로 걸어 찾는다."""
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
    """각 lockfile 커밋 구간 [커밋시각, 다음 커밋시각)에 감염 버전이 잡혀 있었고 그 구간이 공격 창과 겹치면 노출."""
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
    print(f"IOC: {ioc['package']} {ioc['malicious_versions']} | 공격 창: {ioc['window'][0]} ~ {ioc['window'][1]}\n")
    for repo in sorted(p for p in Path(org_dir).iterdir() if (p / ".git").exists()):
        findings = scan_repo(repo, ioc)
        if findings:
            for f in findings:
                print(f"[노출] {repo.name:12s}: {ioc['package']}@{f['version']}을 {f['since']:%m/%d %H:%M}에 도입(커밋 {f['commit']}), {f['until']:%m/%d %H:%M}까지 유지 — 공격 창과 겹침")
                print(f"       전이 경로: {f['path']}")
                print(f"       조치: 이 기간 CI/개발자 환경의 시크릿 로테이션 필요")
        else:
            lock = lock_at(repo, lockfile_history(repo)[-1][1])
            reason = "감염 버전을 거치지 않음" if version_of(lock, ioc["package"]) else f"{ioc['package']} 미사용"
            print(f"[안전] {repo.name:12s}: {reason}")

if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])
