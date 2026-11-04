#!/usr/bin/env python3
"""一条命令把 a2alink 装成技能。

    python install.py                 # 装到 ~/.workbuddy/skills
    python install.py --check         # 只看当前装得怎么样
    python install.py --uninstall     # 卸载（不动身份与审计）

它**不会**改你的 Python 环境、不装任何第三方包、不写系统目录、不联网。
做的事情只有两件：往技能目录写三个文件；打印接下来该干什么。

⚠️ 安全提醒放在最前面，因为它比安装本身重要：
   装上之后，同一台机器上的对话可以互相发消息。发出去的内容会过出站
   DLP 闸门，但闸门只兜已知形态。**内网绝密信息不要通过 Agent 转发**，
   跨机器使用前先确认链路合规。详见 SECURITY.md。
"""

from __future__ import annotations

import argparse
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "src"))

from a2alink import __version__                     # noqa: E402
from a2alink import autostart, skillpack            # noqa: E402

BANNER = f"""
a2alink {__version__} · Agent 跨对话通信
{'-' * 52}
装完之后，你可以对不同对话窗口里的 Agent 说：
  "看看有没有人找我"
  "给 @运维 发消息，说 502 已修复"
  "问一下 @写手，v2 接口的 retry 字段叫什么"

⚠️  内网绝密信息不要通过 Agent 转发到任何外部对话。
    出站有脱敏闸门，但它只兜已知形态，业务数据能不能出域只有人知道。
"""


def main() -> int:
    ap = argparse.ArgumentParser(description="把 a2alink 装成一个 Agent 技能")
    ap.add_argument("--dir", default=None, help="技能根目录（默认 ~/.workbuddy/skills）")
    ap.add_argument("--force", action="store_true", help="覆盖不是本工具装的同名目录")
    ap.add_argument("--no-serve", action="store_true", help="不自动启动本地中继")
    ap.add_argument("--check", action="store_true", help="只检查当前状态")
    ap.add_argument("--uninstall", action="store_true", help="卸载技能")
    args = ap.parse_args()

    print(BANNER)

    if sys.version_info < skillpack.MIN_PYTHON:
        print(f"❌ 需要 Python {skillpack.MIN_PYTHON[0]}.{skillpack.MIN_PYTHON[1]}+，"
              f"当前 {sys.version_info.major}.{sys.version_info.minor}")
        return 2

    root = args.dir or skillpack.default_skills_root()

    if args.uninstall:
        out = skillpack.uninstall(root, force=args.force)
        if out["removed"]:
            print(f"✅ 已卸载 {out['target']}")
            print("   身份、密钥、审计链仍在 ~/.a2alink 下，没有动。")
            return 0
        print(f"未卸载：{out.get('reason')}")
        return 1

    if args.check:
        st = skillpack.status(root)
        for k, v in st.items():
            print(f"  {k}: {v}")
        return 0 if st.get("installed") else 1

    try:
        out = skillpack.install(root, force=args.force)
    except skillpack.SkillPackError as e:
        print(f"❌ {e}")
        return 2

    print(f"✅ 技能已写入 {out['target']}")
    print(f"   启动器 {os.path.join(out['target'], 'scripts', 'a2a.py')}")
    print(f"   源码指向 {skillpack.package_src_root()}")

    if not args.no_serve:
        try:
            info = autostart.ensure("http://127.0.0.1:8787")
            state = "已在运行" if not info.get("started") else "已启动"
            print(f"✅ 本地中继{state} http://127.0.0.1:8787（只听回环地址）")
        except autostart.AutoStartError as e:
            print(f"⚠️  本地中继没起来：{e}")
            print("   不影响安装；第一次发消息时会再试一次。")

    print()
    for line in skillpack.post_install_hint(out["target"])[2:]:
        print(line)
    print()
    print("想直接敲 a2alink 命令的话（可选）：")
    print(f"  {sys.executable} -m pip install -e \"{os.path.dirname(os.path.abspath(__file__))}\"")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
