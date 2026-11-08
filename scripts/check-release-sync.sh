#!/usr/bin/env bash
# 门禁:daedalus-plugins 的 main 不能领先于 latest release。
#
# 为什么:主仓 CI 构建镜像时 `gh release download --pattern '*.plugin.zip'` 取的是
# release 资产,不是 main 的源码。插件修复合进 main 却没发版时,镜像里塞的是旧
# 二进制 —— 而实机门禁会在旧二进制上判 FAIL,让人以为修复无效(真实发生过)。
#
# 判据用 git 祖先关系而非时间戳:release 的 publishedAt 与 commit 时间会因 rebase /
# 延后发版而不一致,比时间会产生假红假绿。
#
# 退出码:0 一致 / 1 main 领先 release / 2 无法判定(无 release、gh 失败、解析失败)。
# 退出码 2 一律视为失败:本门禁 fail-open 就等于没有。
set -uo pipefail

MAIN_REF="${MAIN_REF:-origin/main}"
REPO="${REPO:-Daedalusys/daedalus-plugins}"

die() { printf '%s\n' "$*" >&2; exit 2; }

# release 的 targetCommitish 可能是 sha,也可能是分支名(gh release create --target 的记录形态)。
# 分支名必须先解析成 sha,否则永远比不上 —— 这是最容易漏的形态。
resolve_release_commit() {
    local raw="$1" sha
    [ -n "$raw" ] || return 1
    if sha="$(git rev-parse --verify --quiet "${raw}^{commit}" 2>/dev/null)"; then
        printf '%s\n' "$sha"; return 0
    fi
    # CI 的 checkout 只留 refs/remotes/origin/*:裸分支名(gh release create --target main)
    # 必须再试远端跟踪 ref,否则这个形态在 Actions 里永远解析失败。
    if sha="$(git rev-parse --verify --quiet "refs/remotes/origin/${raw}^{commit}" 2>/dev/null)"; then
        printf '%s\n' "$sha"; return 0
    fi
    # 本地没有该 ref(如分支已删/未 fetch):去远端解析。
    if sha="$(git ls-remote "$REPO" "$raw" 2>/dev/null | head -1 | cut -f1)" && [ -n "$sha" ]; then
        printf '%s\n' "$sha"; return 0
    fi
    return 1
}

main_sha="$(git rev-parse --verify --quiet "${MAIN_REF}^{commit}" 2>/dev/null)" \
    || die "无法解析 $MAIN_REF(先 git fetch origin)"

if [ -n "${RELEASE_TAG:-}" ]; then
    tag="$RELEASE_TAG"
    target="$(gh release view "$tag" --repo "$REPO" --json targetCommitish --jq .targetCommitish 2>/dev/null)" \
        || die "读不到 release $tag 的 targetCommitish(无此 release / gh 无权限 / 网络失败)"
else
    # latest:同时取 tag 名,好让报告可操作。
    read -r tag target < <(gh release view --repo "$REPO" --json tagName,targetCommitish \
        --jq '"\(.tagName) \(.targetCommitish)"' 2>/dev/null) \
        || die "读不到 latest release —— 本仓可能尚无 release(先发 v0.0.1;主仓 gh release download 会 404),或 gh 无权限 / 网络失败。两种情形都视为失败。"
fi

[ -n "${tag:-}" ] || die "本仓尚无 release —— 主仓 CI 的 gh release download 会失败。先发一个 vX.Y.Z"

rel_sha="$(resolve_release_commit "$target")" \
    || die "release $tag 的 targetCommitish='$target' 解析不成 commit(本地无该 ref 且远端也查不到)"

# 解析只是拿到了 sha 字面量;sha 指向的对象不在本地对象库时 merge-base 会报错并
# 退化成"main 领先"的假红,故先显式确认对象存在。
git cat-file -e "${rel_sha}^{commit}" 2>/dev/null \
    || die "release $tag 的锚点 $rel_sha 不在本地对象库(需 git fetch 该 ref 后再跑)"

# main 的 HEAD 已是 release 锚点的祖先(或就是它)→ 一致。
if git merge-base --is-ancestor "$main_sha" "$rel_sha" 2>/dev/null; then
    printf 'OK: main %s 已被 release %s(锚点 %s)覆盖\n' "${main_sha:0:8}" "$tag" "${rel_sha:0:8}"
    exit 0
fi

cat >&2 <<EOF
ERROR: main 领先于 latest release —— 镜像会取到旧插件二进制。

  main HEAD      : $main_sha
  latest release : $tag(锚点 $rel_sha)

后果:daedalus-core 的镜像构建 \`gh release download --pattern '*.plugin.zip'\` 取的是
$tag 的资产,main 上的插件改动**不会**进镜像。实机门禁随后会在旧二进制上判 FAIL,
看起来像"修复无效"(本轮 A6/A7-6 正是如此)。

处置:发一次新 release ——
  gh workflow run release.yml --repo $REPO -f tag=vX.Y.Z
(或 push 一个 v* tag)。发完本门禁会自动转绿。
EOF
exit 1
