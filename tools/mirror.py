#!/usr/bin/env python3
"""镜像分发工具：检查漂移 + 安全推送。

设计上只做两件事：
  1. status —— 每个镜像落后多少提交、tag 齐不齐、有没有人往镜像推过东西
  2. push   —— 自检通过后逐个推 main 和 tags

刻意不做的：
  · 不自动 --force（会无声抹掉别人在镜像上的提交）
  · 不自动 fetch（ls-remote + cat-file 就够判断，不写你的 refs）
  · 不在自检失败时"警告后继续"—— 那是让检查形同虚设

零第三方依赖。用法：

    python tools/mirror.py status
    python tools/mirror.py push
    python tools/mirror.py push --only gitee
"""

from __future__ import annotations

import argparse
import fnmatch
import subprocess
import sys

# 哪也不许去的文件名/路径。命中即拒绝推送。
# 注意 approvals 只匹配目录，不能误伤 src/a2alink/approvals.py。
SENSITIVE_PATTERNS = [
    "identity.json",
    "*.sqlite3",
    "*.sqlite3-wal",
    "*.sqlite3-shm",
    "*.db",
    "policy.json",
    "logs/*",
    "audit.*.jsonl",
    ".env",
    ".env.*",
    "keys/*",
    "*.key",
    "*.key.tmp",
    "*.key.*.old",
    "trust/*",
    "sessions.json",
    "sessions.json.lock",
    "recent.json",
    "approvals/*",
    "approvals.key",
    "registry-*.pid",
    "registry-*.log",
]

# 权威仓库之外的全算镜像
AUTHORITATIVE = "origin"


def _fix_stdout() -> None:
    """Windows 控制台默认不是 UTF-8，中文会炸。"""
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, ValueError):
        pass


def git(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["git", *args], capture_output=True, text=True, encoding="utf-8", errors="replace"
    )


def remotes() -> dict[str, str]:
    """返回 {名字: URL}，不含权威仓库。"""
    out = git("remote", "-v").stdout
    seen: dict[str, str] = {}
    for line in out.splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[0] != AUTHORITATIVE:
            seen.setdefault(parts[0], parts[1])
    return seen


def local_head() -> str | None:
    r = git("rev-parse", "HEAD")
    return r.stdout.strip() if r.returncode == 0 else None


def local_tags() -> set[str]:
    return {t for t in git("tag", "-l").stdout.split() if t}


def remote_refs(url: str) -> tuple[str | None, set[str]] | None:
    """返回 (远端 main 的 sha, 远端 tags 集合)；不可达返回 None。"""
    r = git("ls-remote", "--heads", "--tags", url)
    if r.returncode != 0:
        return None
    head: str | None = None
    tags: set[str] = set()
    for line in r.stdout.splitlines():
        sha, _, ref = line.partition("\t")
        if ref == "refs/heads/main":
            head = sha
        elif ref.startswith("refs/tags/"):
            name = ref[len("refs/tags/"):]
            if not name.endswith("^{}"):  # annotated tag 的解引用行，忽略
                tags.add(name)
    return head, tags


def sensitive_files() -> list[str]:
    tracked = git("ls-files").stdout.splitlines()
    hits = []
    for path in tracked:
        base = path.rsplit("/", 1)[-1]
        for pat in SENSITIVE_PATTERNS:
            # 含 / 的模式按整条路径匹配，否则按文件名匹配
            if ("/" in pat and fnmatch.fnmatch(path, pat)) or (
                "/" not in pat and fnmatch.fnmatch(base, pat)
            ):
                hits.append(path)
                break
    return hits


def self_check() -> bool:
    print("── 推送前自检 ──")
    ok = True

    hits = sensitive_files()
    if hits:
        ok = False
        print(f"⛔ 发现了 {len(hits)} 个不该被跟踪的文件：")
        for h in hits:
            print(f"     {h}")
        print("   先 git rm --cached 清掉。注意：已进历史的不算清掉，")
        print("   那些得用 filter-repo 重写历史，并视为已经泄露。")
    else:
        print("✅ 敏感文件：干净")

    dirty = git("status", "--porcelain").stdout.strip()
    if dirty:
        print("⚠ 工作区有未提交改动（不影响推送已提交的内容，但别推错东西）：")
        for line in dirty.splitlines()[:5]:
            print(f"     {line}")

    # 内嵌凭据的 remote URL：https://user:token@host/...
    for name, url in remotes().items():
        if url.startswith("https://") and "@" in url.split("//", 1)[1].split("/", 1)[0]:
            ok = False
            print(f"⛔ {name} 的 URL 里内嵌了凭据，会连同 .git/config 一起被看到")
            print("   改用 SSH：git remote set-url " + name + " git@<host>:<user>/a2alink.git")

    return ok


def cmd_status(args: argparse.Namespace) -> int:
    rs = remotes()
    if not rs:
        print("没有配置任何镜像 remote。先加一个：")
        print("  git remote add gitee git@gitee.com:<用户名>/a2alink.git")
        return 0

    head = local_head()
    tags = local_tags()
    if not head:
        print("⛔ 读不到本地 HEAD，这不是一个正常的仓库")
        return 2

    print(f"权威仓库：{AUTHORITATIVE}    本地 HEAD：{head[:8]}    tag：{len(tags)} 个\n")
    drifted = 0

    for name, url in sorted(rs.items()):
        print(f"── {name}  {url}")
        refs = remote_refs(url)
        if refs is None:
            print("   ⛔ 不可达（没建仓 / 没授权 / 网络不通）。先 ssh -T 测一下。\n")
            drifted += 1
            continue

        bad = False  # 一个平台只计一次，别把"main 落后 + 缺 tag"算成两个平台
        rhead, rtags = refs
        if rhead is None:
            print("   ○ 远端 main 不存在——还没推过，或仓库是空的")
            bad = True
        elif rhead == head:
            print("   ✅ main 与本地一致")
        elif git("cat-file", "-e", rhead).returncode == 0:
            # 远端那个提交本地有，说明它只是落后
            n = git("rev-list", "--count", f"{rhead}..{head}").stdout.strip()
            print(f"   ⚠ 落后 {n} 个提交")
            bad = True
        else:
            # 本地没有远端那个提交：有人直接往镜像推了东西
            print("   ⛔ 远端有本地不存在的提交——镜像被直接推送过")
            print("      不要直接 force。先看那是什么：")
            print(f"      git fetch {name} main  &&  git log --oneline HEAD..FETCH_HEAD")
            bad = True

        missing = tags - rtags
        extra = rtags - tags
        if not missing and not extra:
            print(f"   ✅ tag 齐全（{len(rtags)} 个）")
        else:
            if missing:
                print(f"   ⚠ 缺 tag：{', '.join(sorted(missing))}")
            if extra:
                print(f"   ⚠ 多出 tag：{', '.join(sorted(extra))}")
            bad = True
        if bad:
            drifted += 1
        print()

    if drifted:
        print(f"结论：{drifted} 个平台需要处理。修漂移前先搞清楚原因，别直接 force。")
    else:
        print("结论：所有镜像都与本地一致。")
    return 0


def cmd_push(args: argparse.Namespace) -> int:
    if not self_check():
        print("\n⛔ 自检没通过，不推。")
        return 2

    rs = remotes()
    targets = {k: v for k, v in rs.items() if not args.only or k in args.only}
    if not targets:
        print("没有匹配的镜像 remote。先用 git remote add 加一个。")
        return 2

    print(f"\n── 开始推送：{', '.join(sorted(targets))} ──")
    failed = []
    for name in sorted(targets):
        for refspec in (["main"], ["--tags"]):
            r = git("push", name, *refspec)
            label = "main" if refspec == ["main"] else "--tags"
            if r.returncode != 0:
                print(f"⛔ {name} {label} 失败：")
                for line in (r.stderr or r.stdout).strip().splitlines()[-4:]:
                    print(f"     {line}")
                failed.append(f"{name}/{label}")
                break
            print(f"✅ {name} {label}")

    if failed:
        print(f"\n⛔ 失败：{', '.join(failed)}")
        print("   若提示 non-fast-forward，说明镜像已经漂移——用 status 查原因，")
        print("   本工具不会替你 force。")
        return 1

    print("\n✅ 全部推完。记得去各平台核对一眼：README 渲染、tag 数、描述里的权威地址。")
    return 0


def main() -> int:
    _fix_stdout()
    p = argparse.ArgumentParser(description="a2alink 镜像分发：漂移检查与安全推送")
    sub = p.add_subparsers(dest="cmd", required=True)

    sub.add_parser("status", help="检查每个镜像落后多少、tag 齐不齐")

    push = sub.add_parser("push", help="自检通过后逐个推 main 和 tags（从不 force）")
    push.add_argument("--only", nargs="+", help="只推指定平台，如 --only gitee")

    args = p.parse_args()
    return cmd_status(args) if args.cmd == "status" else cmd_push(args)


if __name__ == "__main__":
    sys.exit(main())
