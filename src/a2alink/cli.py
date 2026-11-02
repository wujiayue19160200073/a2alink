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
import time
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
                   force=args.force, force_reason=args.reason)
    except EgressBlocked as e:
        print(f"🚫 出站被拦：{e.message}", file=sys.stderr)
        _p(e.result.to_dict())
        print("\n处理方式（三选一）：", file=sys.stderr)
        print("  1) 改内容：把原始数据换成结论/抽象描述（推荐，90% 场景够用）")
        print("  2) 加白名单：确认某条是误报，写进 policy 的 allow_terms")
        print("  3) 人已确认可发：加 --force --reason \"为什么可以发\"（会留审计，责任在人）",
              file=sys.stderr)
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


# ----------------------------------------------------------------------
# 审计日志：查得到、验得动、说得清
# ----------------------------------------------------------------------
def _audit_root(args: argparse.Namespace) -> str:
    """定位审计目录。找不到或有歧义时明确报错，绝不"猜一个最近的"。"""
    if getattr(args, "home", None):
        return os.path.join(args.home, "logs")
    base = os.path.join(os.path.expanduser("~"), ".a2alink")
    if getattr(args, "name", None):
        return os.path.join(base, AgentLink._safe(args.name), "logs")
    if not os.path.isdir(base):
        raise LinkError("no_logs", f"没有找到审计目录 {base}，请用 --name 或 --home 指定")
    cands = [os.path.join(base, n, "logs") for n in sorted(os.listdir(base))]
    cands = [c for c in cands if os.path.isdir(c)]
    if not cands:
        raise LinkError("no_logs", f"{base} 下没有任何 Agent 的审计目录")
    if len(cands) == 1:
        return cands[0]
    names = ", ".join(os.path.basename(os.path.dirname(c)) for c in cands)
    raise LinkError("ambiguous_home",
                    f"本机有多个 Agent 的日志（{names}），请用 --name 指定查哪一个")


def _open_log(args: argparse.Namespace) -> Any:
    from .audit import AuditLog
    return AuditLog(_audit_root(args), "cli:readonly", readonly=True)


def _fmt_rec(r: Dict[str, Any]) -> str:
    ts = (r.get("iso") or "")[11:23] or "-"
    dec = str(r.get("decision", ""))
    mark = {"deny": "✗", "drop": "✗", "redact": "~", "allow": "·", "note": " "}.get(dec, " ")
    d = r.get("detail") or {}
    extra = " ".join(f"{k}={v}" for k, v in list(d.items())[:4] if k != "action")
    # trace 在这里截断只为排版；查的时候支持短 id 前缀匹配，见 cmd_trace
    trace = (r.get("trace") or "-")[:20]
    return (f"{ts} {mark} {dec.upper():6} {str(r.get('reason','')):22} "
            f"{trace:16} {extra}")


def cmd_logs(args: argparse.Namespace) -> int:
    log = _open_log(args)
    action = args.action

    if action == "verify":
        rep = log.verify()
        if rep["ok"]:
            print(f"✅ 审计链完整：{rep['records']} 条记录，{len(rep['chains'])} 条链")
            for name, info in rep["chains"].items():
                print(f"   {name}: {info['records']} 条，最后 seq={info['last_seq']}")
        else:
            print(f"❌ 审计链异常：{len(rep['errors'])} 处问题", file=sys.stderr)
            for e in rep["errors"][:20]:
                print(f"   {e.get('kind')} @ {e.get('file')}:{e.get('line','-')} "
                      f"seq={e.get('seq','-')} {e.get('detail','')}", file=sys.stderr)
            print("\n这意味着这份日志不能作为证据使用。"
                  "先别清理现场，保留原始文件，再按 docs/logging.md 的取证流程走。",
                  file=sys.stderr)
        return 0 if rep["ok"] else 5

    if action == "stats":
        _p(log.stats())
        return 0

    if action == "seal":
        if not args.yes:
            print("归档会移动日志文件到 archive/，不会删除任何记录。加 --yes 确认。",
                  file=sys.stderr)
            return 2
        try:
            m = log.seal(args.as_name or None)
        except OSError as e:
            print(f"❌ 归档失败：{e}", file=sys.stderr)
            print("   原始日志没有被删除，但可能停在半途。先 ls 一下 archive 目录确认。",
                  file=sys.stderr)
            return 1
        print(f"✅ 已归档 {len(m['files'])} 个文件到 archive/{m['name']}/")
        for f in m["files"]:
            print(f"   {f['name']}  {f['records']} 条  sha256={f['sha256'][:16]}…")
        print("   MANIFEST.json 里记了每个文件的完整 sha256；"
              "把证据交给别人时，连同它一起给。")
        return 0

    if action == "export":
        recs = log.read(limit=args.limit or 0, trace=args.trace, event=args.event,
                        decision=args.decision, reason=args.reason, since=args.since_s)
        out = args.out or "-"
        data = "\n".join(json.dumps(r, ensure_ascii=False) for r in recs) + "\n"
        if out == "-":
            sys.stdout.write(data)
        else:
            with open(out, "w", encoding="utf-8") as f:
                f.write(data)
            print(f"已导出 {len(recs)} 条到 {out}", file=sys.stderr)
        return 0

    # tail / search
    recs = log.read(limit=args.limit, trace=args.trace, event=args.event,
                    decision=args.decision, reason=args.reason, since=args.since_s)
    if not recs:
        print("（没有匹配的记录）")
        return 0
    if getattr(args, "as_json", False):
        # 给脚本和取证用：不截断、不排版，原样输出。
        # 人眼看表格，机器看 JSON —— 两件事不要混在一个格式里。
        for r in recs:
            print(json.dumps(r, ensure_ascii=False))
        return 0
    print(f"{'时间':12} {'':1} {'结果':6} {'理由码':22} {'trace(截断)':20} 摘要")
    print("-" * 104)
    for r in recs:
        print(_fmt_rec(r))
    print("\n提示：trace 在表格里是截断的，`a2alink trace` 支持短 id 前缀匹配；"
          "要完整值加 --json。")
    if args.summary:
        denied = sum(1 for r in recs if r.get("decision") in ("deny", "drop"))
        print(f"\n共 {len(recs)} 条，其中被拦 {denied} 条")
    return 0


def cmd_trace(args: argparse.Namespace) -> int:
    """把一条消息的一生摊开：本地的决策 + 服务端的投递。"""
    log = _open_log(args)

    # 支持短 id 前缀：表格里 trace 是截断显示的，人一定会直接复制过来查。
    # 与其让人自己去翻完整值，不如这里认前缀——和 git 的短 hash 一个道理。
    tid = args.trace_id
    all_ids = {r.get("trace") for r in log.read(limit=0) if r.get("trace")}
    if tid not in all_ids:
        cands = sorted(i for i in all_ids if i.startswith(tid))
        if len(cands) == 1:
            tid = cands[0]
        elif len(cands) > 1:
            print(f"前缀 {tid} 匹配到多条 trace，请给长一点：", file=sys.stderr)
            for c in cands[:10]:
                print(f"  {c}", file=sys.stderr)
            return 2
    local = log.read(limit=500, trace=tid)

    print(f"trace {tid}")
    print("=" * 92)
    print(f"\n【本地决策链】{_audit_root(args)}")
    if not local:
        print("  （本机没有这条 trace 的记录——它可能是别人发起的，或用另一个 --name 跑的）")
    for r in local:
        print("  " + _fmt_rec(r))
        d = r.get("detail") or {}
        if r.get("preview"):
            print(f"      预览: {r['preview']}")
        if d.get("force_reason"):
            print(f"      人confirmed: {d['force_reason']}")

    # 服务端视角：能连上就问，连不上就明说，不假装查过了
    try:
        c = _client(args)
        srv = c._api("GET", f"/v1/trace/{tid}")
    except LinkError as e:
        print(f"\n【服务端视角】查不到：{e.message}")
        print("  注意：这不等于'服务端没收到'，只等于'现在问不到'。")
        return 0
    print(f"\n【服务端视角】{c.registry}")
    for m in srv.get("messages", []):
        print(f"  {m.get('from_agent','')[:14]:14} → {m.get('to_type')}:{str(m.get('to_id'))[:14]:14} "
              f"msg={str(m.get('id'))[:14]}")
    for d in srv.get("my_deliveries", []):
        print(f"  投递 seq={d.get('message_seq')} state={d.get('state')} "
              f"reason={d.get('reason') or '-'}")
    if not srv.get("messages"):
        print("  （服务端没有这条 trace 的消息记录）")
    return 0


def cmd_incident(args: argparse.Namespace) -> int:
    """出事后第一眼要看的东西：这段时间谁放行了什么、谁被拦了。

    刻意把 override 放在最前面。因为事后复盘时，
    "系统拦了多少"通常不是关键，"哪几条是人拍板放过去的"才是。
    """
    from .audit import OVERRIDE_REASONS
    log = _open_log(args)
    recs = log.read(limit=0, since=args.since_s)
    if not recs:
        print(f"最近 {args.hours} 小时没有审计记录")
        return 0

    overrides = [r for r in recs if r.get("reason") in OVERRIDE_REASONS
                 and r.get("decision") != "drop"]
    # "想强行放行但没写理由、被系统挡回去"——这不是事故，反而是好消息，
    # 但必须单独列出来：它说明有人在那段时间里试图绕过闸门。
    blocked_attempts = [r for r in recs if r.get("reason") in OVERRIDE_REASONS
                        and r.get("decision") == "drop"]
    denies = [r for r in recs if r.get("decision") in ("deny", "drop")
              and r.get("reason") not in OVERRIDE_REASONS]
    redacts = [r for r in recs if r.get("decision") == "redact"]

    print(f"审计摘要 · 最近 {args.hours} 小时 · {len(recs)} 条记录")
    print("=" * 92)
    print(f"拦截 {len(denies)} 条 · 脱敏 {len(redacts)} 条 · 人工放行 {len(overrides)} 条"
          f" · 试图放行被拒 {len(blocked_attempts)} 次")

    if overrides:
        print("\n⚠️  人工强行放行（这几条是责任在人，不是系统）：")
        for r in overrides:
            d = r.get("detail") or {}
            print(f"  {(r.get('iso') or '')[11:19]}  {r.get('reason')}")
            print(f"      trace={r.get('trace') or '-'}  peer={d.get('peer','-')}")
            print(f"      理由: {d.get('force_reason') or '（空白！！这条不合规）'}")
            if r.get("preview"):
                print(f"      内容预览: {r['preview']}")

    if blocked_attempts:
        print("\n⚑ 试图强行放行但未提供理由（已被系统拒绝）：")
        for r in blocked_attempts:
            d = r.get("detail") or {}
            print(f"  {(r.get('iso') or '')[11:19]}  trace={(r.get('trace') or '-')[:20]}"
                  f"  peer={d.get('peer','-')}")

    if denies:
        print("\n被拦明细：")
        for r in denies[: args.list_max]:
            d = r.get("detail") or {}
            rules = d.get("rules") or ""
            print(f"  {(r.get('iso') or '')[11:19]}  {r.get('reason'):20} "
                  f"trace={(r.get('trace') or '-')[:16]:16} {rules}")
        if len(denies) > args.list_max:
            print(f"  …另有 {len(denies) - args.list_max} 条，用 logs search --decision deny 看全")

    print("\n下一步：")
    print("  a2alink logs verify                 # 先确认日志本身没被动过")
    print("  a2alink trace <trace_id>            # 摊开某一条的完整链路")
    print("  a2alink logs export --out case.jsonl # 固定证据，别再写盘")
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
    s.add_argument("--force", action="store_true",
                   help="人已确认，强制放行（必须配 --reason，留审计）")
    s.add_argument("--reason", default="", metavar="理由",
                   help="强制放行的理由，至少 8 个字，会写进审计链")
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

    # ---- 审计日志：本机就能查，不依赖注册中心 ----
    lg = sub.add_parser("logs", help="审计日志：查 / 验 / 导出 / 归档（可离线）")
    lgs = lg.add_subparsers(dest="action", required=True)

    def _filters(sp: argparse.ArgumentParser) -> None:
        sp.add_argument("--trace", default=None, help="按 trace_id 过滤")
        sp.add_argument("--event", default=None, help="事件名，支持正则")
        sp.add_argument("--decision", default=None,
                        choices=["allow", "redact", "deny", "drop", "note"])
        sp.add_argument("--reason", default=None, help="理由码，支持正则")
        sp.add_argument("--hours", type=float, default=24, help="时间窗口（小时），0=不限")

    lt = lgs.add_parser("tail", help="看最近的记录")
    lt.add_argument("-n", "--limit", type=int, default=30)
    lt.add_argument("--summary", action="store_true")
    lt.add_argument("--json", dest="as_json", action="store_true",
                    help="输出原始 JSON（不截断，供脚本与取证使用）")
    _filters(lt)

    lq = lgs.add_parser("search", help="按条件搜（同 tail，只是默认给更多）")
    lq.add_argument("-n", "--limit", type=int, default=200)
    lq.add_argument("--summary", action="store_true")
    lq.add_argument("--json", dest="as_json", action="store_true",
                    help="输出原始 JSON（不截断，供脚本与取证使用）")
    _filters(lq)

    lgs.add_parser("verify", help="校验哈希链有没有断（能不能当证据）")
    lgs.add_parser("stats", help="按理由码统计")

    le = lgs.add_parser("export", help="导出为 JSONL，用于固定证据")
    le.add_argument("--out", default=None, help="输出文件，默认打到标准输出")
    le.add_argument("--limit", type=int, default=0, help="0=不限")
    _filters(le)

    lse = lgs.add_parser("seal", help="归档为证据包（移动，不删除）")
    lse.add_argument("--yes", action="store_true")
    lse.add_argument("--as", dest="as_name", default=None, help="归档批次名")

    lg.set_defaults(func=cmd_logs)

    tr = sub.add_parser("trace", help="按 trace_id 摊开一条消息的完整链路")
    tr.add_argument("trace_id")
    tr.set_defaults(func=cmd_trace)

    inc = sub.add_parser("incident", help="事故速览：谁放行了什么、谁被拦了")
    inc.add_argument("--hours", type=float, default=24)
    inc.add_argument("--list-max", type=int, default=20)
    inc.set_defaults(func=cmd_incident)

    sub.add_parser("doctor", help="上线前自检").set_defaults(func=cmd_doctor)
    sub.add_parser("demo", help="30 秒演示").set_defaults(func=cmd_demo)
    return p


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    # 时间窗口换算成绝对时间戳，供审计查询使用
    hours = float(getattr(args, "hours", 24) or 0)
    args.since_s = 0.0 if hours <= 0 else time.time() - hours * 3600
    # guard / logs 不需要身份，提前分发，避免因连不上注册中心而失败。
    # 这条很重要：出问题的时候注册中心往往正好连不上，查日志不能被它拖住。
    if args.cmd in ("guard", "logs"):
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
