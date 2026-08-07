#!/usr/bin/env bash
# 모의 조직(레포 3개)을 생성한다: api-server만 공격 창(11/24~26) 안에 감염 버전 chalk@5.6.1을 설치한 이력을 가진다.
set -euo pipefail
cd "$(dirname "$0")"
rm -rf demo-org && mkdir demo-org && cd demo-org

mklock() {
  python3 - "$1" <<'EOF' > package-lock.json
import json, sys
chalk_ver = sys.argv[1]
lock = {'name': 'api-server', 'lockfileVersion': 3, 'packages': {
    '': {'dependencies': {'express': '^4.19.0'}},
    'node_modules/express': {'version': '4.19.2', 'dependencies': {'debug': '^4.3.4'}},
    'node_modules/debug': {'version': '4.3.5', 'dependencies': {'chalk': '^5.6.0'}},
    'node_modules/chalk': {'version': chalk_ver}}}
print(json.dumps(lock, indent=1))
EOF
}

commit_at() { GIT_AUTHOR_DATE="$1" GIT_COMMITTER_DATE="$1" git commit -qm "$2"; }

# 레포 1: api-server — 공격 창 안에 감염 버전 5.6.1 도입 후 5.6.2로 탈출
mkdir api-server && cd api-server && git init -q
mklock 5.6.0 && git add -A && commit_at "2025-11-20T10:00:00+09:00" "chore: initial deps (chalk 5.6.0)"
mklock 5.6.1 && git add -A && commit_at "2025-11-25T14:30:00+09:00" "chore: bump deps (chalk 5.6.1)"
mklock 5.6.2 && git add -A && commit_at "2025-11-28T09:00:00+09:00" "chore: bump deps (chalk 5.6.2)"
cd ..

# 레포 2: web-frontend — 감염 버전을 거치지 않고 5.6.0 → 5.6.2
mkdir web-frontend && cd web-frontend && git init -q
mklock 5.6.0 && git add -A && commit_at "2025-11-10T11:00:00+09:00" "chore: initial deps (chalk 5.6.0)"
mklock 5.6.2 && git add -A && commit_at "2025-11-29T16:00:00+09:00" "chore: bump deps (chalk 5.6.2)"
cd ..

# 레포 3: mobile-app — chalk 미사용
mkdir mobile-app && cd mobile-app && git init -q
python3 - <<'EOF' > package-lock.json
import json
lock = {'name': 'mobile-app', 'lockfileVersion': 3, 'packages': {
    '': {'dependencies': {'react-native': '^0.74.0'}},
    'node_modules/react-native': {'version': '0.74.1'}}}
print(json.dumps(lock, indent=1))
EOF
git add -A && commit_at "2025-11-15T13:00:00+09:00" "chore: initial deps"
cd ..

echo "demo-org 생성 완료 — 실행: python3 poc/scan.py poc/demo-org poc/ioc-demo.json"
