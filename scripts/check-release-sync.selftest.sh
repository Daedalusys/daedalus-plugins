#!/usr/bin/env bash
# check-release-sync.sh 的判定逻辑自检:用假 gh 与本地 git 仓库,不联网。
set -euo pipefail
HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
fail=0
st() { if [ "$1" = "$2" ]; then printf '  PASS  %s\n' "$3"
       else printf '  FAIL  %s (期望 %s,实际 %s)\n' "$3" "$1" "$2"; fail=$((fail + 1)); fi }

tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT
cd "$tmp"
git init -q repo && cd repo
git config user.email t@t && git config user.name t
echo a > f && git add f && git commit -qm one
C1="$(git rev-parse HEAD)"
echo b >> f && git add f && git commit -qm two
C2="$(git rev-parse HEAD)"

# 假 gh:按 FAKE_TARGET 返回 targetCommitish;请求 tagName 时按真实 --json 形态
# 返回 "<tag> <target>" 一行(脚本的 latest 腿用 read 拆这两个字段)。
mkdir -p "$tmp/bin"
cat > "$tmp/bin/gh" <<'EOS'
#!/usr/bin/env bash
case "$*" in
  *"release view"*)
    if [ "${FAKE_NO_RELEASE:-0}" = 1 ]; then echo "release not found" >&2; exit 1; fi
    case "$*" in
      *tagName*) printf 'v9.9.9 %s\n' "${FAKE_TARGET:-}" ;;
      *)         printf '%s\n' "${FAKE_TARGET:-}" ;;
    esac
    ;;
  *) exit 0 ;;
esac
EOS
chmod +x "$tmp/bin/gh"
export PATH="$tmp/bin:$PATH"
# 自检声明「不联网」:把 REPO 指向本地仓库,resolve 的 ls-remote 兜底腿就不会外连。
export REPO="$tmp/repo"

# 1) release 锚在 main HEAD → 一致
out="$(FAKE_TARGET="$C2" MAIN_REF="$C2" bash "$HERE/check-release-sync.sh" 2>&1)" && rc=0 || rc=$?
st 0 "$rc" "release 锚点 == main → 一致(0)"

# 2) release 锚在旧 commit,main 已领先 → 不一致
out="$(FAKE_TARGET="$C1" MAIN_REF="$C2" bash "$HERE/check-release-sync.sh" 2>&1)" && rc=0 || rc=$?
st 1 "$rc" "main 领先 release → 失败(1)"
if ! printf '%s' "$out" | grep -q "$C1"; then
    printf '  FAIL  报告里应出现 release 锚点 sha,实得: %s\n' "$out"; fail=$((fail + 1))
fi

# 3) targetCommitish 是分支名 → 必须解析成该分支当前 sha
FAKE_TARGET="HEAD" MAIN_REF="$C2" bash "$HERE/check-release-sync.sh" >/dev/null 2>&1 && rc=0 || rc=$?
st 0 "$rc" "targetCommitish 是分支名 → 解析后一致(0)"

# 4) 无 release → 显式失败(2),不放行
FAKE_NO_RELEASE=1 MAIN_REF="$C2" bash "$HERE/check-release-sync.sh" >/dev/null 2>&1 && rc=0 || rc=$?
st 2 "$rc" "无 release → 显式失败(2)"

# 5) 无法解析 release commit → 显式失败
FAKE_TARGET="nonexistent-ref" MAIN_REF="$C2" bash "$HERE/check-release-sync.sh" >/dev/null 2>&1 && rc=0 || rc=$?
st 2 "$rc" "targetCommitish 解析失败 → 显式失败(2)"

if [ "$fail" -eq 0 ]; then echo "RESULT: RELEASE-SYNC SELFTEST PASS"; exit 0; fi
echo "RESULT: RELEASE-SYNC SELFTEST FAIL ($fail)"; exit 1
