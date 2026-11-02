"""a2alink 命令行。

用法速查：
    a2alink registry                      # 本地起注册中心（只监听 127.0.0.1）
    a2alink whoami                        # 看自己的身份
    a2alink discover --cap k8s            # 按能力找人
    a2alink friend request bob "求助"      # 加好友（对方必须同意）
    a2alink friend pending                # 看谁想加我
    a2alink friend accept <request_id>
    a2alink group create 运维协同 --mode unan
    a2alink group invite <gid> bob
    a2alink group vote <gid> <pid> yes
    a2alink send bob --text "帮我查一下 502"
    a2alink inbox --wait 5
    a2alink serve --name my-agent --cap ops,k8s --adapter echo
    a2alink guard check 待发内容.md        # 出站前体检（防内网信息外泄）
    a2alink doctor                        # 上线前自检
    a2alink demo                          # 30 秒看完整个机制
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Any, Dict, List, Optional

from . import __version__
from .adapters import EchoAdapter, LLMAdapter
from .client import AgentLink, EgressBlocked, LinkError, LoopHalt
from .guard import COMPLIANCE_CHECKLIST, EgressGuard, compliance_report
from .registry import Registry, serve

DEFAULT_REGISTRY = os.environ.get("A2ALINK_REGISTRY", "http://127.0.0.1:8787")


def _p(obj: Any) -> None:
    if isinstance(obj, str):
        print(obj)
    else:
        print(json.dumps(obj, ensure_ascii=False, indent=2))


def _client(args: argparse.Namespace, **kw: Any) -> AgentLink:
    caps: List[str] = []
    for g in (args.cap or []):
        caps.extend([c.strip() for c in str(g).split(",") if c.strip()])
    return AgentLink(registry=args.registry, name=args.name,
                     capabilities=caps, home=args.home,
                     peer_scope=args.scope, **kw)


# ==========================================================================
def cmd_registry(args: argparse.Namespace) -> int:
    reg = Registry(args.db, invite_code=args.invite_code)
    if args.host not in ("127.0.0.1", "localhost"):
        print("⚠️  警告：注册中心将监听非回环地址。任何能访问该端口的人都可以注册身份、"
              "尝试加好友。\n    公网部署前请务必设置 --invite-code，并在前面加 TLS 反代。",
              file=sys.stderr)
    serve(reg, host=args.host, port=args.port, verbose=args.verbose)
    return 0


def cmd_whoami(args: argparse.Namespace) -> int:
    c = _client(args)
    _p({"agent_id": c.agent_id, "name": c.name, "registry": c.registry,
        "home": c.home, "capabilities": c.capabilities,
        "outbound_scope": c.peer_scope,
        "watchdog": {"max_messages": c.wd.max_messages, "max_tokens": c.wd.max_tokens,
                     "max_wall_seconds": c.wd.max_wall_seconds}})
    return 0


def cmd_discover(args: argparse.Namespace) -> int:
    c = _client(args)
    rows = c.discover(args.capability, args.q, args.limit)
    if not rows:
        print("（没有匹配的 Agent。冷启动阶段这是正常的——先自己起两个跑通再说。）")
        return 0
    for a in rows:
        print(f"- {a['name']:<20} {a['agent_id']}  caps={','.join(a['capabilities']) or '-'}")
        if a.get("description"):
            print(f"  {a['description']}")
    return 0


def cmd_friend(args: argparse.Namespace) -> int:
    c = _client(args)
    if args.action == "request":
        _p(c.friend_request(args.who, args.message or ""))
    elif args.action == "pending":
        reqs = c.pending_requests("in")
        if not reqs:
            print("（没有待处理的好友申请）")
        for r in reqs:
            print(f"- {r['id']}  from={r['from_agent']}  msg={r['message']!r}  {r['state']}")
    elif args.action == "accept":
        _p(c.friend_accept(args.who))
    elif args.action == "reject":
        _p(c.friend_reject(args.who))
    elif args.action == "list":
        fs = c.friends()
        if not fs:
            print("（还没有好友。注意：未成为好友前，双方无法互发任何消息。）")
        for f in fs:
            p = f["peer"]
            print(f"- {p['name']:<20} {p['agent_id']}  caps={','.join(p['capabilities']) or '-'}")
    elif args.action == "rm":
        _p(c.unfriend(args.who))
    return 0


def cmd_group(args: argparse.Namespace) -> int:
    c = _client(args)
    if args.action == "create":
        _p(c.group_create(args.name, join_mode=args.mode, quorum=args.quorum,
                          proposal_ttl=args.ttl, trusted_direct=getattr(args, "trusted", True),
                          consent_ttl=getattr(args, "consent_ttl", 259200)))
    elif args.action == "invite":
        _p(c.group_invite(args.gid, args.who))
    elif args.action == "vote":
        _p(c.group_vote(args.gid, args.pid, args.vote))
    elif args.action == "consent":
        _p(c.group_consent(args.gid, args.pid, bool(args.accept), args.reason))
    elif args.action == "privacy":
        _p({"silent_members": c._api("GET", f"/v1/groups/{args.gid}/privacy",
                                     qs=f"days={args.days}").get("silent_members", [])})
    elif args.action == "show":
        _p(c.group_info(args.gid))
    elif args.action == "props":
        _p(c.group_proposals(args.gid))
    elif args.action == "remove":
        _p(c.group_remove(args.gid, args.who))
    return 0


def cmd_send(args: argparse.Namespace) -> int:
    c = _client(args)
    if args.payload_file:
        with open(args.payload_file, "r", encoding="utf-8") as f:
            payload = json.load(f)
    elif args.json:
        payload = json.loads(args.json)
    elif args.text:
        payload = {"instruction": args.text}
    else:
        print("需要 --text / --json / --payload-file 之一", file=sys.stderr)
        return 2
    try:
        s = c.send(args.to, payload, act=args.act, stage=args.stage,
                   ttl_hops=args.hops, ttl_seconds=args.ttl,
                   max_messages=args.max_messages, max_tokens=args.max_tokens,
                   force=args.force)
    except EgressBlocked as e:
        print(f"🚫 出站被拦：{e.message}", file=sys.stderr)
        _p(e.result.to_dict())
        print("\n处理方式（三选一）：", file=sys.stderr)
        print("  1) 改内容：把原始数据换成结论/抽象描述（推荐，90% 场景够用）")
        print("  2) 加白名单：确认某条是误报，写进 policy 的 allow_terms")
        print("  3) 人已确认可发：加 --force（会留审计记录，责任在人）", file=sys.stderr)
        return 3
    except LoopHalt as e:
        print(f"⛔ {e.message}", file=sys.stderr)
        return 4
    print(f"✅ 已发送 message_id={s.env.id} conversation={s.env.conversation_id} "
          f"投递={s.delivered_to} 跳数={s.env.ttl_hops}")
    if s.egress and s.egress.action == "redact":
        print(f"   已脱敏 {len(s.egress.findings)} 处（密级判定={s.egress.level}）")
    if s.verdict and s.verdict.action != "pass":
        print(f"   看门狗提示：{s.verdict.reasons}")
    return 0


def cmd_inbox(args: argparse.Namespace) -> int:
    c = _client(args)
    items = c.recv(wait=args.wait, limit=args.limit, auto_ack=args.ack)
    if not items:
        print("（没有新消息）")
    for r in items:
        tag = "🚫隔离" if r.quarantine else "✅"
        if r.verdict and r.verdict.action == "stop":
            tag = "⛔熔断"
        print(f"\n{tag} from={r.env.from_agent} act={r.env.act} stage={r.env.stage} "
              f"conv={r.env.conversation_id} hops={r.env.ttl_hops} seq={r.seq}")
        if r.verdict and r.verdict.reasons:
            print(f"   看门狗：{'; '.join(r.verdict.reasons)}")
        if r.ingress and r.ingress.findings:
            print(f"   入站检测：{len(r.ingress.findings)} 条可疑特征")
        if r.text:
            print("   " + r.text.replace("\n", "\n   "))
    return 0


def cmd_serve(args: argparse.Namespace) -> int:
    c = _client(args)
    adapter: Any
    if args.adapter == "echo":
        adapter = EchoAdapter()
    elif args.adapter == "llm":
        print("llm 适配器需要你自己接：见 examples/with_llm.py", file=sys.stderr)
        return 2
    else:
        adapter = EchoAdapter()
    print(f"[a2alink] {c.name} 开始监听（adapter={adapter.name}）。Ctrl-C 退出。")
    try:
        stats = c.run(adapter.handle, poll=args.poll, max_rounds=args.rounds)
    except KeyboardInterrupt:
        stats = {"interrupted": 1}
    _p(stats)
    _p(c.wd.stats())
    return 0


def cmd_guard(args: argparse.Namespace) -> int:
    if args.path and args.path != "-":
        with open(args.path, "r", encoding="utf-8") as f:
            text = f.read()
    else:
        text = sys.stdin.read()
    report = compliance_report(text, scope=args.scope, deny_terms=args.deny_term)
    print(report)
    g = EgressGuard(scope=args.scope, deny_terms=args.deny_term)
    r = g.check(text)
    if r.action == "block":
        print("\n结论：🚫 不允许发出。按上面的命中项逐条处理，不要直接脱敏了事。")
        return 3
    if r.action == "redact":
        print("\n结论：⚠️ 需脱敏后才能发。以下是可以发的版本：\n" + "-" * 60)
        print(r.text)
        print("-" * 60)
        return 0
    print("\n结论：✅ 未命中已知规则。但规则不等于合规审查，业务数据仍需人判断。")
    return 0


def cmd_doctor(args: argparse.Namespace) -> int:
    print(f"a2alink {__version__} 自检\n" + "=" * 62)
    ok = True
    print(f"[1] Python: {sys.version.split()[0]}", end="")
    if sys.version_info >= (3, 10):
        print("  ✅")
    else:
        print("  ❌ 需要 3.10+")
        ok = False

    print(f"[2] 注册中心: {args.registry}", end="")
    try:
        c = _client(args)
        me = c.me()
        print(f"  ✅ 已连接，身份={me['name']}")
    except (LinkError, OSError) as e:
        print(f"  ⚠️ {e}")
        print("    本地开发请先跑：a2alink registry")
        c = None

    if c:
        idp = c._id_path
        print(f"[3] 身份文件: {idp}", end="")
        if os.path.exists(idp):
            mode = os.stat(idp).st_mode & 0o777
            if os.name != "nt" and mode & 0o077:
                print(f"  ⚠️ 权限 {oct(mode)}，建议 chmod 600")
                ok = False
            else:
                print("  ✅")
        else:
            print("  ❌ 不存在")
            ok = False
        print(f"[4] 身份数量: 好友 {len(c.friends())} 个", end="")
        print("  ✅" if c.friends() else "  ⚠️ 还没有好友，无法收发消息")
        print(f"[5] 出站信任域: {c.peer_scope}  "
              f"({'最严，公网默认' if c.peer_scope == 'wan' else '较宽松，请确认对端可信'})")
        print(f"[6] 看门狗: 消息上限 {c.wd.max_messages} / token 上限 {c.wd.max_tokens} "
              f"/ 时长上限 {c.wd.max_wall_seconds:.0f}s")
        if c.wd.max_messages > 50 or c.wd.max_tokens > 200000:
            print("    ⚠️ 阈值偏高，一次失控循环可能烧掉不少钱")
            ok = False
        print(f"[7] 出站 DLP: {'启用' if c.egress else '未启用'}（fail-closed）")
        print(f"[8] 入站注入检测: {'启用' if c.ingress else '未启用'}")

    print("\n" + COMPLIANCE_CHECKLIST)
    print("自检结论：" + ("✅ 基本可用（安全仍需人判）" if ok else "⚠️ 有项目需要处理"))
    return 0 if ok else 1


def cmd_demo(args: argparse.Namespace) -> int:
    from .demo import run_demo
    return run_demo()


def cmd_pending(args: argparse.Namespace) -> int:
    """待办清单。这个命令存在的理由很朴素：没人通知你，事情就会永久挂起。"""
    c = _client(args)
    d = c.pending_actions()
    if not d["count"]:
        print("没有待处理的事。")
        return 0
    for it in d["invites"]:
        print(f"[入群邀请] {it['group_name']}  ← {it['created_by']}  ({it['admission']})")
        print(f"   a2alink group consent {it['group_id']} {it['id']} --accept"
              f"   （不加 --accept 就是拒绝，拒绝后对方 24h 内不能再邀你）")
    for it in d["votes"]:
        print(f"[待投票]   {it['group_name']}  提案 {it['id']}  目标 {it['target']}")
        print(f"   a2alink group vote {it['group_id']} {it['id']} yes|no")
    return 0


# ==========================================================================
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="a2alink", description="A2A Link — AI Agent 对等通信（含防泄密闸门与死循环看门狗）")
    p.add_argument("--version", action="version", version=f"a2alink {__version__}")
    p.add_argument("--registry", default=DEFAULT_REGISTRY, help="注册中心地址")
    p.add_argument("--name", default=None, help="本 Agent 名称（默认自动生成）")
    p.add_argument("--cap", action="append", default=None, metavar="ops,k8s",
                   help="能力标签，逗号分隔，可重复写")
    p.add_argument("--home", default=None, help="身份文件目录，默认 ~/.a2alink/<name>")
    p.add_argument("--scope", default="wan", choices=["local", "lan", "wan"],
                   help="默认对端信任域（wan 最严，默认）")
    sub = p.add_subparsers(dest="cmd", required=True)

    r = sub.add_parser("registry", help="启动注册中心")
    r.add_argument("--db", default="a2alink.sqlite3")
    r.add_argument("--host", default="127.0.0.1")
    r.add_argument("--port", type=int, default=8787)
    r.add_argument("--invite-code", default=None, help="非空时注册必须提供邀请码")
    r.add_argument("-v", "--verbose", action="store_true")
    r.set_defaults(func=cmd_registry)

    sub.add_parser("whoami", help="查看当前身份").set_defaults(func=cmd_whoami)
    sub.add_parser("pending", help="我欠着的动作：待表态的邀请 + 待投的票").set_defaults(
        func=cmd_pending)

    d = sub.add_parser("discover", help="按能力发现 Agent")
    d.add_argument("--capability", default=None)
    d.add_argument("--q", default=None)
    d.add_argument("--limit", type=int, default=30)
    d.set_defaults(func=cmd_discover)

    f = sub.add_parser("friend", help="好友管理（双向同意）")
    fs = f.add_subparsers(dest="action", required=True)
    fr = fs.add_parser("request")
    fr.add_argument("who")
    fr.add_argument("message", nargs="?", default="")
    fs.add_parser("pending")
    for a in ("accept", "reject", "rm"):
        sp = fs.add_parser(a)
        sp.add_argument("who")
    fs.add_parser("list")
    f.set_defaults(func=cmd_friend)

    g = sub.add_parser("group", help="群组与入群表决")
    gs = g.add_subparsers(dest="action", required=True)
    gc = gs.add_parser("create")
    gc.add_argument("name")
    gc.add_argument("--mode", default="unan", choices=["unan", "majority", "admin"])
    gc.add_argument("--quorum", type=float, default=0.0)
    gc.add_argument("--ttl", type=float, default=86400)
    gc.add_argument("--no-trusted", dest="trusted", action="store_false",
                    help="关闭受信直入：即使邀请人和受邀者是好友，也要走全员表决")
    gc.add_argument("--consent-ttl", type=float, default=259200,
                    help="邀请等待受邀者同意的有效期（秒），超时作废")
    g.set_defaults(trusted=True)
    gi = gs.add_parser("invite")
    gi.add_argument("gid")
    gi.add_argument("who")
    gv = gs.add_parser("vote")
    gv.add_argument("gid")
    gv.add_argument("pid")
    gv.add_argument("vote", choices=["yes", "no"])
    gcn = gs.add_parser("consent", help="受邀者表态：同意/拒绝入群")
    gcn.add_argument("gid")
    gcn.add_argument("pid")
    gcn.add_argument("--accept", action="store_true", help="同意；不加则为拒绝")
    gcn.add_argument("--reason", default="")
    gpr = gs.add_parser("privacy", help="隐私体检：入群后从未发言的成员")
    gpr.add_argument("gid")
    gpr.add_argument("--days", type=float, default=7.0)
    gsh = gs.add_parser("show")
    gsh.add_argument("gid")
    gp = gs.add_parser("props")
    gp.add_argument("gid")
    gr = gs.add_parser("remove")
    gr.add_argument("gid")
    gr.add_argument("who")
    g.set_defaults(func=cmd_group)

    s = sub.add_parser("send", help="发消息（内置出站脱敏 + 熔断）")
    s.add_argument("to")
    s.add_argument("--text", default=None)
    s.add_argument("--json", default=None)
    s.add_argument("--payload-file", default=None)
    s.add_argument("--act", default="task")
    s.add_argument("--stage", default="open")
    s.add_argument("--hops", type=int, default=4)
    s.add_argument("--ttl", type=float, default=600)
    s.add_argument("--max-messages", type=int, default=12)
    s.add_argument("--max-tokens", type=int, default=12000)
    s.add_argument("--force", action="store_true", help="人已确认，强制放行（留审计）")
    s.set_defaults(func=cmd_send)

    i = sub.add_parser("inbox", help="收取消息（内置注入检测）")
    i.add_argument("--wait", type=float, default=0)
    i.add_argument("--limit", type=int, default=20)
    i.add_argument("--ack", action="store_true", default=True)
    i.set_defaults(func=cmd_inbox)

    sv = sub.add_parser("serve", help="以某个适配器常驻")
    sv.add_argument("--adapter", default="echo", choices=["echo", "llm"])
    sv.add_argument("--poll", type=float, default=1.0)
    sv.add_argument("--rounds", type=int, default=200)
    sv.set_defaults(func=cmd_serve)

    gd = sub.add_parser("guard", help="出站内容体检（防泄密）")
    gds = gd.add_subparsers(dest="action", required=True)
    gchk = gds.add_parser("check")
    gchk.add_argument("path", nargs="?", default="-", help="文件路径，- 表示 stdin")
    gchk.add_argument("--deny-term", action="append", default=None)
    gd.set_defaults(func=cmd_guard)

    sub.add_parser("doctor", help="上线前自检").set_defaults(func=cmd_doctor)
    sub.add_parser("demo", help="30 秒演示").set_defaults(func=cmd_demo)
    return p


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    # guard 子命令不需要身份，提前分发，避免因连不上注册中心而失败
    if args.cmd == "guard":
        return args.func(args)
    try:
        return int(args.func(args) or 0)
    except LinkError as e:
        print(f"❌ {e}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
