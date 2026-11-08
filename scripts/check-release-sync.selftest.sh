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

# 6) 分支名形态 + CI checkout 形态:只有 origin/main,没有本地 main。
#    gh release create --target main 记的是裸分支名;actions/checkout 不建本地分支。
#    REPO 指向不存在的路径 → ls-remote 兜底腿必失败,证明解析走的是本地
#    origin/<branch> 而非联网(CI 里 persist-credentials=false,兜底腿不可靠)。
git init -q --bare "$tmp/remote.git"
git remote add origin "$tmp/remote.git"
git push -q origin "$C2:refs/heads/main"
git checkout -q --detach "$C1"
git update-ref -d refs/heads/main 2>/dev/null || true
git fetch -q origin
out="$(FAKE_TARGET="main" MAIN_REF="origin/main" REPO="$tmp/does-not-exist.git" \
       bash "$HERE/check-release-sync.sh" 2>&1)" && rc=0 || rc=$?
st 0 "$rc" "targetCommitish 是裸分支名(仅 origin/<branch> 存在)→ 解析后一致(0)"
if ! printf '%s' "$out" | grep -q "^OK:"; then
    printf '  FAIL  应打印 OK 行,实得: %s\n' "$out"; fail=$((fail + 1))
fi

# 7) 远端解析出的 sha 不在本地对象库(分支未 fetch 的形态)→ 显式失败(2),
#    不能拿 merge-base 的报错当"main 领先"输出误导性结论。
git init -q "$tmp/other" && cd "$tmp/other"
git config user.email t@t && git config user.name t
echo o > g && git add g && git commit -qm other
git push -q "$tmp/remote.git" "HEAD:refs/heads/release-branch"
cd "$tmp/repo"
out="$(FAKE_TARGET="release-branch" MAIN_REF="origin/main" REPO="$tmp/remote.git" \
       bash "$HERE/check-release-sync.sh" 2>&1)" && rc=0 || rc=$?
st 2 "$rc" "release 锚点对象不在本地 → 显式失败(2)"

if [ "$fail" -eq 0 ]; then echo "RESULT: RELEASE-SYNC SELFTEST PASS"; exit 0; fi
echo "RESULT: RELEASE-SYNC SELFTEST FAIL ($fail)"; exit 1
