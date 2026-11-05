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
    local = args.host in ("127.0.0.1", "localhost", "::1")
    mesh = bool(getattr(args, "local_mesh", False)) and local
    if getattr(args, "local_mesh", False) and not local:
        # 静默降级比报错更危险：用户以为开了同机互信，其实没开（或反过来）。
        print("⚠️  --local-mesh 只在监听回环地址时生效；本机将对外提供注册服务，"
              "已强制关闭同机互信。", file=sys.stderr)
    reg = Registry(args.db, invite_code=args.invite_code, local_mesh=mesh)
    if not local:
        print("⚠️  警告：注册中心将监听非回环地址。任何能访问该端口的人都可以注册身份、"
              "尝试加好友。\n    公网部署前请务必设置 --invite-code，并在前面加 TLS 反代。",
              file=sys.stderr)
    if mesh:
        print("[a2alink] 同机互信已开启（local_mesh）：本机会话互发消息免好友审批，"
              "每次放行都会写入审计。", file=sys.stderr)
    try:
        serve(reg, host=args.host, port=args.port, verbose=args.verbose)
    finally:
        # Ctrl-C 退出也要关连接：WAL 模式下不关会留下 -wal/-shm，
        # 下次启动虽然能恢复，但"干净退出"应该是默认而不是运气。
        reg.close()
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
        # 密码学状态放在第一行可见位置。一条消息"是不是真的是他发的"
        # 比"内容是什么"更需要先回答。
        crypto_bits = []
        crypto_bits.append("已验签" if r.authenticated else "⚠️未验签")
        if r.decrypted:
            crypto_bits.append("端到端加密")
        elif not r.reject_reason:
            crypto_bits.append("明文")
        trust = (r.trust or {}).get("decision")
        if trust in ("new", "match", "skipped"):
            crypto_bits.append({"new": "首次固定", "match": "公钥一致",
                                "skipped": "未校验公钥"}[trust])
        elif trust:
            crypto_bits.append(f"⚠️公钥{trust}")
        print(f"\n{tag} from={r.env.from_agent} act={r.env.act} stage={r.env.stage} "
              f"conv={r.env.conversation_id} hops={r.env.ttl_hops} seq={r.seq}")
        print(f"   [{' · '.join(crypto_bits)}]")
        if r.reject_reason:
            print(f"   ⛔ 拒收原因：{r.reject_reason}")
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


def _home_of(args: argparse.Namespace) -> str:
    """与 AgentLink 相同的 home 解析逻辑。密钥命令要能离线跑，
    所以不能靠构造 client 来拿路径（构造 client 会去连注册中心）。"""
    if getattr(args, "home", None):
        return args.home
    name = getattr(args, "name", None) or "default"
    safe = "".join(c for c in name if c.isalnum() or c in "-_")[:40] or "default"
    return os.path.join(os.path.expanduser("~"), ".a2alink", safe)


def cmd_keys(args: argparse.Namespace) -> int:
    from .crypto import CryptoError, KeyStore, fingerprint_of
    from .trust import POLICIES, TrustStore

    action = args.action
    home = _home_of(args)
    policy = getattr(args, "trust_policy", "tofu")

    # ---------- 离线命令：不连注册中心 ----------
    if action == "show":
        ks = KeyStore(os.path.join(home, "keys")).load_or_create()
        d = ks.describe()
        print(f"身份目录  {home}")
        print(f"签名指纹  {d['sign_fingerprint']}   ← 把它念给对方核对")
        print(f"交换指纹  {d['kex_fingerprint']}")
        print(f"签名公钥  {d['sign_pub']}")
        print(f"交换公钥  {d['kex_pub']}")
        print(f"私钥文件  {', '.join(d['private_files'])}")
        print("\n公钥可以随便给；私钥永远不要复制、截图、提交仓库。")
        return 0

    if action == "list":
        ts = TrustStore(os.path.join(home, "trust"), policy=policy)
        rows = ts.list()
        if not rows:
            print("（还没有固定的对端公钥）")
            return 0
        print(f"{'agent':26} {'指纹':40} {'来源':10} 变更")
        print("-" * 96)
        for r in rows:
            print(f"{r['agent_id']:26} {r.get('sign_fp',''):40} "
                  f"{r.get('source',''):10} {len(r.get('changes') or [])} 次")
        return 0

    if action == "forget":
        ts = TrustStore(os.path.join(home, "trust"), policy=policy)
        if not args.yes:
            print("删除固定记录之后，下次见面会重新走 TOFU，"
                  "等于暂时放弃对这个对端的防冒充能力。加 --yes 确认。", file=sys.stderr)
            return 2
        ok = ts.forget(args.who)
        print("已删除" if ok else "没有这条记录")
        return 0 if ok else 1

    # ---------- 需要连注册中心的命令 ----------
    c = _client(args)

    if action == "publish":
        out = c._publish_keys(reason=args.reason or "手动上传公钥")
        c._audit("crypto.keys", "allow", "crypto.keys_published",
                 detail={"fp": out.get("key_fp", "")})
        _p({"key_fp": out.get("key_fp"), "old_fp": out.get("old_fp"),
            "note": out.get("warning") or "公钥已登记"})
        return 0

    if action == "rotate":
        if not args.yes:
            print("轮换会生成新密钥对，旧私钥归档到 keys/*.old。\n"
                  "⚠️  轮换后所有对端都会因为指纹变化而拒收你的消息，\n"
                  "    直到它们带外确认后重新 pin。加 --yes 确认。", file=sys.stderr)
            return 2
        out = c.keys.rotate()
        c._audit("crypto.rotate", "note", "crypto.key_rotated",
                 detail={"old_fp": out.get("old_fingerprint", ""),
                         "new_fp": out.get("new_fingerprint", "")})
        pub = c._publish_keys(reason="轮换密钥")
        print(f"旧指纹  {out.get('old_fingerprint')}")
        print(f"新指纹  {out.get('new_fingerprint')}")
        print(f"归档为  keys/*.{out.get('archived_as')}.old")
        print(f"\n已登记到注册中心。请把新指纹 {out.get('new_fingerprint')} "
              f"通过带外渠道通知所有对端。")
        return 0

    if action == "peer":
        info = c.peer_public(c.resolve(args.who), refresh=True)
        if not info.get("sign_pub"):
            print(f"注册中心没有 {args.who} 的公钥（对方可能是 0.1.x 版本）",
                  file=sys.stderr)
            return 1
        from .crypto import b64d
        print(f"agent    {c.resolve(args.who)}")
        print(f"签名指纹 {fingerprint_of(b64d(info['sign_pub']))}")
        if info.get("kex_pub"):
            print(f"交换指纹 {fingerprint_of(b64d(info['kex_pub']))}")
        print("\n⚠️  以上指纹来自注册中心，**未经核对**。")
        print("    要真正防冒充，请通过另一个渠道（电话/当面/内部 IM）")
        print("    向对方索取指纹并逐段比对，一致后再执行 keys pin。")
        return 0

    if action == "pin":
        peer = c.resolve(args.who)
        info = c.peer_public(peer, refresh=True)
        if not info.get("sign_pub"):
            print("拿不到对方公钥，无法固定", file=sys.stderr)
            return 1
        from .crypto import b64d
        sign_pub = b64d(info["sign_pub"])
        kex_pub = b64d(info["kex_pub"]) if info.get("kex_pub") else None
        fp = fingerprint_of(sign_pub)
        print(f"对端    {peer}")
        print(f"待固定  {fp}")
        if args.expect:
            if args.expect.replace("-", "").lower() != fp.replace("-", "").lower():
                print(f"\n❌ 指纹不匹配！你提供的 {args.expect}，"
                      f"注册中心给的 {fp}。\n"
                      f"   这可能是注册中心在换钥匙——不要继续，先查清楚。",
                      file=sys.stderr)
                return 6
            print("✅ 与你提供的指纹一致")
        if not args.yes:
            print("\n确认这是对方的真实指纹后，加 --yes 写入固定记录。",
                  file=sys.stderr)
            return 2
        out = c.trust.pin(peer, sign_pub, kex_pub, source="manual", note=args.note or "")
        print(f"已固定 {out['fp']}" + ("（替换了旧记录）" if out["replaced"] else ""))
        return 0

    print(f"未知操作 {action}", file=sys.stderr)
    return 2


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

        # ---- 密码学状态：这几项才是 v0.2 之后最容易配错的地方 ----
        print(f"[9] 签名指纹: {c.keys.signing.fingerprint}")
        print(f"    加密策略: {c.encrypt} / 信任策略: {c.trust.policy}")
        if c.encrypt == "never":
            print("    ⚠️ encrypt=never：所有单聊都是明文，注册中心能读全文")
            ok = False
        if c.trust.policy == "off":
            print("    ⚠️ trust_policy=off：不做公钥固定，注册中心可以冒充任何对端")
            ok = False

        key_dir = os.path.join(c.home, "keys")
        perm_ok = True
        if os.name != "nt":
            for f in ("signing.key", "kex.key"):
                p_ = os.path.join(key_dir, f)
                if os.path.exists(p_) and (os.stat(p_).st_mode & 0o077):
                    perm_ok = False
                    print(f"    ❌ {f} 权限过宽，chmod 600 后再上线")
                    ok = False
        print(f"[10] 私钥权限: {'✅' if perm_ok else '❌'}（{key_dir}）")

        trusted = c.trust.list()
        manual = [t for t in trusted if t.get("source") == "manual"]
        tofu_only = [t for t in trusted if t.get("source") != "manual"]
        print(f"[11] 已固定对端: {len(trusted)} 个"
              f"（人工核对 {len(manual)}，仅 TOFU {len(tofu_only)}）", end="")
        if tofu_only:
            print(f"\n    ⚠️ {len(tofu_only)} 个对端的指纹从未被人核对过，"
                  f"首次通信可能被中间人利用\n"
                  f"       核对方法：a2alink keys show 念给对方，"
                  f"然后 a2alink keys pin <对端> --expect <指纹>")
        else:
            print("  ✅" if trusted else "  ⚠️ 还没有固定任何对端")

        changed = [r for r in c.audit.read(limit=2000)
                   if r.get("reason") == "crypto.key_changed"]
        if changed:
            print(f"[12] ⚠️ 近期有 {len(changed)} 次公钥变更被拒收 —— "
                  f"可能是对方换机器，也可能是有人在冒充。用 `a2alink incident` 查。")

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
# v0.3：会话身份 / 一键安装 / 跨对话收发
# ==========================================================================
def _ident(args: argparse.Namespace):
    """解析当前会话身份。仅在 --as 与"猜"的情况下多说一句。"""
    from . import sessions
    who = getattr(args, "as_", None)
    ident = sessions.current(who=who)
    if ident.source == "latest" and not who:
        # 猜了就必须说。静默地"用了最近那个会话"是最容易发错人的场景。
        print(f"[a2alink] 未检测到会话 ID，按最近活跃的会话处理：{ident.display}"
              f"（如不对，用 --as <名字> 指定）", file=sys.stderr)
    elif ident.source == "fallback":
        print(f"[a2alink] 未检测到会话 ID，已创建独立身份 {ident.display}"
              f"（{ident.agent_name}）", file=sys.stderr)
    return ident


def _session_client(args: argparse.Namespace, **kw: Any):
    """会话身份 + 自动中继，一步到位。

    这是"一键"的全部秘密：调用方不需要先起服务、先注册、先加好友。
    """
    from . import autostart
    ident = _ident(args)
    res = autostart.ensure(args.registry, quiet=True,
                           local_mesh=kw.pop("local_mesh", True))
    if res.get("managed") and not res.get("alive", True):
        raise SystemExit(f"本地中继不可用：{args.registry}")
    caps: List[str] = []
    for g in (args.cap or []):
        caps.extend([c.strip() for c in str(g).split(",") if c.strip()])
    # 注册时的三行提示（身份、指纹、私钥路径）对第一次用的人有用，对
    # 第 20 次调用就是噪音，还会把 check 的摘要冲散。这里自己控制：
    # 只有新建身份时打一行到 stderr，其余一律安静。
    fresh = not os.path.exists(os.path.join(ident.home, "identity.json"))
    old_quiet = os.environ.get("A2ALINK_QUIET")
    os.environ["A2ALINK_QUIET"] = "1"
    try:
        c = AgentLink(registry=args.registry, name=ident.agent_name,
                      capabilities=caps, home=ident.home,
                      peer_scope=args.scope, **kw)
    finally:
        if old_quiet is None:
            os.environ.pop("A2ALINK_QUIET", None)
        else:
            os.environ["A2ALINK_QUIET"] = old_quiet
    if fresh:
        print(f"[a2alink] {ident.display} 首次上线：{c.agent_id}"
              f"  私钥 {c.keys.root}（勿提交仓库）", file=sys.stderr)
    return c, ident


def _rel(ts: float) -> str:
    d = max(0.0, time.time() - float(ts or 0))
    if d < 60:
        return "刚刚"
    if d < 3600:
        return f"{int(d // 60)} 分钟前"
    if d < 86400:
        return f"{int(d // 3600)} 小时前"
    return f"{int(d // 86400)} 天前"


def _name_map(c: AgentLink, limit: int = 500) -> Dict[str, str]:
    """agent_id → 给人看的名字。

    注册中心只知道 ``s-3f2a1b44``，别名只在本机 sessions.json 里。两边拼起来
    才是用户认得的那个称呼；只查一边的结果是"来消息了，来自 s-3f2a1b44"，
    等于没说。
    """
    from . import sessions
    try:
        rows = c.discover(None, None, limit)
    except Exception:
        rows = []
    id2name = {str(a.get("agent_id")): str(a.get("name") or "")
               for a in rows if a.get("agent_id")}
    try:
        label_of = {str(r.get("agent_name")): str(r.get("label"))
                    for r in sessions.SessionStore().all().values()
                    if r.get("label")}
    except (OSError, ValueError):
        label_of = {}
    out: Dict[str, str] = {}
    for aid, name in id2name.items():
        lbl = label_of.get(name)
        out[aid] = f"@{lbl}（{name}）" if lbl else name
    return out


def _body_of(r: Any) -> str:
    """从载荷里取人要看的那句话。

    直接打印 ``r.text`` 会把 ``instruction``/``intent`` 这些键名和整段围栏
    声明一起喷出来，人读着累，Agent 也会把键名当正文。取正文、单独包围栏，
    既保留防护标记又不妨碍阅读。
    """
    p = r.env.payload if isinstance(getattr(r.env, "payload", None), dict) else {}
    for k in ("instruction", "text", "message", "content", "question"):
        v = p.get(k)
        if isinstance(v, str) and v.strip():
            return v.strip()
    if not p:
        return ""
    return json.dumps(p, ensure_ascii=False)[:2000]


def _recent_path(home: str) -> str:
    return os.path.join(home, "recent.json")


def _remember(home: str, items: List[Any], cap: int = 200) -> None:
    """记下"这条消息是谁发的"，供 reply 用。

    只存元数据 + 截断后的内容摘要，不存全文——本地缓存不该变成第二个
    明文消息库，那是把加密和"日志不存原文"的努力绕过去了。
    """
    p = _recent_path(home)
    try:
        with open(p, "r", encoding="utf-8") as f:
            cache = json.load(f)
        if not isinstance(cache, dict):
            cache = {}
    except (OSError, ValueError):
        cache = {}
    for r in items:
        if not r.env or not r.env.id:
            continue
        cache[r.env.id] = {
            "from": r.env.from_agent,
            "conversation_id": r.env.conversation_id,
            "act": r.env.act,
            "ts": r.env.created_at if hasattr(r.env, "created_at") else time.time(),
            "preview": (r.text or "")[:80],
        }
    if len(cache) > cap:
        for k in sorted(cache, key=lambda k: float(cache[k].get("ts") or 0))[:len(cache) - cap]:
            cache.pop(k, None)
    try:
        os.makedirs(home, exist_ok=True)
        with open(p, "w", encoding="utf-8") as f:
            json.dump(cache, f, ensure_ascii=False)
        os.chmod(p, 0o600)
    except OSError:
        pass


def _lookup(home: str, msg_id: str) -> Optional[Dict[str, Any]]:
    try:
        with open(_recent_path(home), "r", encoding="utf-8") as f:
            return json.load(f).get(msg_id)
    except (OSError, ValueError, AttributeError):
        return None


def _resolve_target(to: str) -> str:
    """把 ``@运维`` 这类本机会话别名翻成协议里的 agent 名。

    别名只在本机有意义，注册中心不知道"运维"是谁。**先查别名再交给协议**，
    是因为用户说"给运维发"时，他想的是那个对话，不是某个远端同名 Agent。
    查不到就原样传下去，让 client.resolve 按名字/ID 去注册中心找。
    """
    from . import sessions
    t = str(to or "").strip()
    bare = t[1:] if t.startswith("@") else t
    if not bare:
        return t
    try:
        rec = sessions.SessionStore().by_label(bare)
    except (OSError, ValueError):
        rec = None
    return rec["agent_name"] if rec else bare


def _print_received(items: List[Any], names: Dict[str, str]) -> None:
    for r in items:
        who = names.get(r.env.from_agent) or r.env.from_agent
        bad = r.quarantine or bool(r.reject_reason)
        tag = "🚫" if bad else "·"
        print(f"  {tag} [{r.env.act}] {who}  id={r.env.id}")
        if r.reject_reason:
            print(f"      ⛔ 拒收：{r.reject_reason}")
            continue
        if r.quarantine:
            print("      🚫 检出可疑指令，已隔离，内容不进入上下文"
                  "（a2alink logs tail 可查判定依据）")
            continue
        body = _body_of(r) or "（空内容）"
        # 围栏必须留着：这段文本就是要进 Agent 上下文的东西，
        # 去掉标记等于把"这是外部数据"这个信息也去掉了。
        print(f'      <untrusted_external_content source="agent:{r.env.from_agent}">')
        for line in body.splitlines()[:12]:
            print(f"      {line}")
        print("      </untrusted_external_content>")


# ---------------------------------------------------------------- session
def cmd_session(args: argparse.Namespace) -> int:
    from . import sessions
    st = sessions.SessionStore()
    action = args.action

    if action == "whoami":
        ident = _ident(args)
        _p(ident.to_dict())
        return 0

    if action == "name":
        ident = _ident(args)
        try:
            rec = st.bind(ident.sid, label=args.label)
        except sessions.SessionError as e:
            print(f"❌ {e}", file=sys.stderr)
            return 2
        # 起名顺手把身份登记到中继。不起这一步，别人 @ 你时会得到
        # "找不到名为 s-xxxx 的 Agent"——名字存在本地，但注册中心不认识它。
        # 起名 = 上线，这是用户的心理模型。
        online = ""
        try:
            _c, _i = _session_client(args)
            online = f"，已在 {args.registry} 上线"
        except Exception as e:
            online = f"，但上线失败（{e}）；下次收信时会自动补登记"
        print(f"✅ 当前对话已命名为 @{rec['label']}"
              f"（协议身份 {rec['agent_name']}，改名不会改变它）{online}")
        print(f"   别人可以这样找你：a2alink say @{rec['label']} \"...\"")
        return 0

    if action == "release":
        ok = st.release_label(args.label)
        print(f"✅ 已释放别名 @{args.label}" if ok else f"（别名 @{args.label} 不存在）")
        return 0 if ok else 1

    if action == "list":
        rows = st.all()
        if not rows:
            print("（本机还没有任何会话。在新对话里跑一次 a2alink check 就会自动登记。）")
            return 0
        cur = None
        try:
            cur = _ident(args).sid
        except Exception:
            pass
        print(f"{'':2} {'别名':<12} {'协议身份':<16} {'最后活跃':<12} 会话 ID")
        for sid, r in sorted(rows.items(), key=lambda kv: -float(kv[1].get("last_seen") or 0)):
            mark = "→" if sid == cur else " "
            print(f"{mark:2} {'@' + r['label'] if r.get('label') else '-':<12} "
                  f"{r.get('agent_name', ''):<16} "
                  f"{_rel(r.get('last_seen')):<12} {sid}")
        return 0

    if action == "forget":
        ident = _ident(args)
        target = args.who or ident.sid
        sid = st.resolve(target)
        if not sid:
            print(f"❌ 找不到会话 {target!r}", file=sys.stderr)
            return 2
        if args.drop_files:
            print("⚠️  同时删除身份目录：私钥和审计链会一起消失，之后无法再验证"
                  "该身份发过的消息。", file=sys.stderr)
            if not args.yes:
                print("   确认请加 --yes。", file=sys.stderr)
                return 2
        ok = st.forget(sid, drop_files=args.drop_files)
        print("✅ 已从会话表移除" if ok else "（没有这条记录）")
        return 0 if ok else 1

    print("未知动作", file=sys.stderr)
    return 2


# ------------------------------------------------------------------ skill
def cmd_skill(args: argparse.Namespace) -> int:
    from . import skillpack
    root = args.dir or skillpack.default_skills_root()
    try:
        if args.action == "install":
            out = skillpack.install(root, force=args.force, dry_run=args.dry_run)
            if out.get("dry_run"):
                print("（预演，未写盘）将写入：")
                for p in out["would_write"]:
                    print(f"  + {p}")
                return 0
            if out.get("upgraded_from") and out["upgraded_from"] != out["version"]:
                print(f"✅ 已从 v{out['upgraded_from']} 升级到 v{out['version']}")
            for line in skillpack.post_install_hint(out["target"]):
                print(line)
            return 0

        if args.action == "status":
            st = skillpack.status(root)
            _p(st)
            if st.get("installed") and st.get("outdated"):
                print("\n提示：技能版本与当前库不一致，执行 a2alink skill install 更新。")
            return 0 if st.get("installed") else 1

        if args.action == "uninstall":
            out = skillpack.uninstall(root, force=args.force)
            if out["removed"]:
                print(f"✅ 已删除 {out['target']}")
                print("   身份、密钥、审计链仍在 ~/.a2alink 下，没有动。")
                return 0
            print(f"未删除：{out.get('reason')}"
                  + (f"\n{out['hint']}" if out.get("hint") else ""))
            return 1
    except skillpack.SkillPackError as e:
        print(f"❌ {e}", file=sys.stderr)
        return 2
    return 2


# --------------------------------------------------------------------- up
def _set_will_if_asked(args: argparse.Namespace) -> None:
    """`up --will ... --will-to ...` 的落地。

    为什么不设计成"单独一条命令"：那样用户会在"起来了"和"立遗嘱"之间
    漏掉第二步，而漏掉的后果正是这个功能要防的事——崩溃时没人知道。
    高频动作里能合并的步骤，不要留给记性。
    """
    text = str(getattr(args, "will_text", "") or "").strip()
    if not text:
        return
    to = str(getattr(args, "will_to", "") or "").strip()
    if not to:
        print("⚠️  给了 --will 但没给 --will-to，遗嘱没立（不知道发给谁）。",
              file=sys.stderr)
        return
    try:
        c, _ = _session_client(args)
        out = c.set_will(_resolve_target(to), text,
                         ttl_seconds=int(getattr(args, "will_ttl", 600)))
        print(f"📜 遗嘱已立：{out['deliver_after']} 秒无动静就通知 {to}")
    except Exception as e:
        print(f"⚠️  遗嘱没立上：{e}", file=sys.stderr)


def cmd_up(args: argparse.Namespace) -> int:
    from . import autostart
    try:
        out = autostart.ensure(args.registry, quiet=False,
                               local_mesh=not args.no_mesh)
    except autostart.AutoStartError as e:
        print(f"❌ {e}", file=sys.stderr)
        return 2
    # 中继起来之后再立遗嘱，否则没地方存它。
    _set_will_if_asked(args)
    if not out.get("managed"):
        print(f"远端注册中心：{'在线' if out.get('alive') else '不可达'}  {args.registry}")
        return 0 if out.get("alive") else 3
    if not out.get("started"):
        print(f"✅ 本地中继已在运行 {args.registry}"
              + (f"（pid {out['pid']}）" if out.get("pid") else ""))
    return 0


def cmd_down(args: argparse.Namespace) -> int:
    from . import autostart
    # 正常下线用不上遗嘱——遗嘱是给"意外消失"准备的。
    # 不撤的话，对方会在十分钟后收到一条"我掉线了"，而人其实好好的。
    if not getattr(args, "keep_will", False):
        try:
            c, _ = _session_client(args)
            info = c.will_info()
            if info.get("will") and not info.get("fired"):
                c.clear_will()
                print("📜 遗嘱已撤销（正常下线，用不上它）")
        except Exception:
            pass
    out = autostart.stop(args.registry)
    if out.get("stopped"):
        return 0
    reason = out.get("reason")
    if reason == "not_running":
        print("（中继没在跑）")
        return 0
    if reason == "not_managed":
        print("⚠️  该端口上的 a2alink 不是本工具拉起的，没有动它。", file=sys.stderr)
        print(f"   {out.get('hint', '')}", file=sys.stderr)
        return 1
    if reason == "remote":
        print("远端注册中心不归本机管。", file=sys.stderr)
        return 1
    print(f"停止失败：{reason}", file=sys.stderr)
    return 1


# -------------------------------------------------------------------- say
def cmd_say(args: argparse.Namespace) -> int:
    """发一条消息，不等回复。"""
    try:
        c, ident = _session_client(args)
    except Exception as e:
        print(f"❌ {e}", file=sys.stderr)
        return 2
    act = args.act or "event"
    payload = {"instruction": args.text, "intent": "note"}
    if args.json:
        payload = json.loads(args.json)
    try:
        s = c.send(_resolve_target(args.to), payload, act=act, stage=args.stage,
                   conversation_id=args.conversation,
                   force=args.force, force_reason=args.reason)
    except EgressBlocked as e:
        print(f"🚫 出站被拦：{e.message}", file=sys.stderr)
        _p(e.result.to_dict())
        print("\n三选一：1) 改内容只给结论 2) 加白名单 3) "
              "人已确认可发 → --force --reason \"为什么可以发\"", file=sys.stderr)
        return 3
    except LoopHalt as e:
        print(f"⛔ {e.message}", file=sys.stderr)
        return 4
    except LinkError as e:
        if e.code == "not_friends":
            print("🚫 不是好友，且这个中继没开同机互信。\n"
                  "   本机中继：a2alink up（默认开启 local_mesh）\n"
                  "   跨机对端：先 a2alink friend request / accept", file=sys.stderr)
            return 5
        print(f"❌ {e.message}", file=sys.stderr)
        return 2
    print(f"✅ 已发送 → {args.to}  id={s.env.id}  conv={s.env.conversation_id}")
    print(f"   署名 {ident.display}  对方下次收信时可见")
    return 0


# -------------------------------------------------------------------- ask
def cmd_ask(args: argparse.Namespace) -> int:
    """提问并等回答。等不到就如实说等不到，不重试。"""
    try:
        c, ident = _session_client(args)
    except Exception as e:
        print(f"❌ {e}", file=sys.stderr)
        return 2
    payload = {"instruction": args.text, "intent": "question", "need_reply": True}
    try:
        s = c.send(_resolve_target(args.to), payload, act="task", stage="open",
                   conversation_id=args.conversation,
                   force=args.force, force_reason=args.reason)
    except EgressBlocked as e:
        print(f"🚫 出站被拦：{e.message}", file=sys.stderr)
        return 3
    except LoopHalt as e:
        print(f"⛔ {e.message}", file=sys.stderr)
        return 4
    except LinkError as e:
        if e.code == "not_friends":
            print("🚫 不是好友（且中继未开同机互信）。见 a2alink up 的说明。",
                  file=sys.stderr)
            return 5
        print(f"❌ {e.message}", file=sys.stderr)
        return 2

    print(f"📤 已提问 → {args.to}  id={s.env.id}")
    wait = float(args.wait or 0)
    if wait <= 0:
        print("   （--wait 0：已投递，不等待回答。对方下次收信时可见。）")
        return 0

    names = _name_map(c)
    others: List[Any] = []
    answer = None
    deadline = time.monotonic() + wait
    while time.monotonic() < deadline:
        left = deadline - time.monotonic()
        try:
            items = c.recv(wait=min(2.0, max(0.2, left)), limit=20)
        except LinkError as e:
            print(f"⚠️  收信出错：{e.message}", file=sys.stderr)
            break
        for r in items:
            # 认"回复这条"最准；同一 conversation 里对方的后续消息也算回答，
            # 因为对方可能用 say 而不是 reply（人手写命令时很常见）。
            # 注意不能用 delivered_to 比 from_agent——那是投递份数，不是身份。
            if r.env.in_reply_to == s.env.id or (
                    r.env.conversation_id == s.env.conversation_id
                    and r.env.from_agent != c.agent_id):
                answer = r
            else:
                others.append(r)
        if answer:
            break

    if others:
        _remember(ident.home, others)
        print(f"\n📥 期间还收到 {len(others)} 条其它消息：")
        _print_received(others, names)

    if not answer:
        print(f"\n⏳ {wait:.0f} 秒内没有回答。消息已投递，对方被唤起收信时能看到。")
        print("   不要循环重发同一个问题——这正是协议要防的死循环。")
        return 6

    _remember(ident.home, [answer])
    who = names.get(answer.env.from_agent) or answer.env.from_agent
    print(f"\n📥 收到回答 · 来自 {who} · id={answer.env.id}")
    if answer.reject_reason:
        print(f"   ⛔ 但这条被拒收了：{answer.reject_reason}")
        return 7
    body = _body_of(answer) or "（空）"
    print(f'   <untrusted_external_content source="agent:{answer.env.from_agent}">')
    for line in body.splitlines()[:20]:
        print(f"   {line}")
    print("   </untrusted_external_content>")
    return 0


# ------------------------------------------------------------------ reply
def cmd_reply(args: argparse.Namespace) -> int:
    """回复某条收到的消息。

    必须带 in_reply_to 和 stage=done：一条问答链走完就结束，
    不留下"还能继续聊"的余地。这是本协议和 IM 最本质的区别。
    """
    try:
        c, ident = _session_client(args)
    except Exception as e:
        print(f"❌ {e}", file=sys.stderr)
        return 2
    meta = _lookup(ident.home, args.msg_id)
    if not meta:
        print(f"❌ 本地没有这条消息的记录（{args.msg_id}）。\n"
              f"   可能不是这个会话收的，或已被清理。\n"
              f"   可以直接发：a2alink say <对方> \"...\"", file=sys.stderr)
        return 2
    to = args.to or meta.get("from")
    if not to:
        print("❌ 不知道回复给谁，请用 --to 指定。", file=sys.stderr)
        return 2
    payload = {"instruction": args.text, "intent": "answer"}
    try:
        s = c.send(to, payload, act="result", stage="done",
                   conversation_id=meta.get("conversation_id"),
                   in_reply_to=args.msg_id)
    except EgressBlocked as e:
        print(f"🚫 出站被拦：{e.message}", file=sys.stderr)
        return 3
    except LoopHalt as e:
        print(f"⛔ {e.message}", file=sys.stderr)
        return 4
    except LinkError as e:
        print(f"❌ {e.message}", file=sys.stderr)
        return 2
    # meta 里记的是 agent_id，直接打出来是 agt-xxxx，人认不出是谁。
    # 多花一次 discover 换一句人话，值。
    shown = _name_map(c).get(to, to)
    print(f"✅ 已回复 → {shown}  id={s.env.id}（这条链到此结束）")
    return 0


# ------------------------------------------------------------------ check
def cmd_check(args: argparse.Namespace) -> int:
    """收信 + 摘要。Agent 每次上手通信前都该先跑这一条。"""
    try:
        c, ident = _session_client(args)
    except Exception as e:
        print(f"❌ {e}", file=sys.stderr)
        return 2
    try:
        items = c.recv(wait=args.wait, limit=args.limit)
    except LinkError as e:
        print(f"❌ 收信失败：{e.message}", file=sys.stderr)
        return 2

    names = _name_map(c)
    head = f"📬 {ident.display}（{ident.agent_name}）"
    if not items:
        print(f"{head} 没有未读消息。")
    else:
        print(f"{head} 共 {len(items)} 条未读：")
        _remember(ident.home, items)
        for i, r in enumerate(items, 1):
            who = names.get(r.env.from_agent) or r.env.from_agent
            flag = "🚫" if (r.quarantine or r.reject_reason) else (
                "❓" if r.env.act == "task" else "·")
            body = "" if (r.quarantine or r.reject_reason) else _body_of(r)
            print(f"\n{i}. {flag} [{r.env.act}] 来自 {who}  {_rel(r.env.created_at)}")
            print(f"   id={r.env.id}")
            if r.reject_reason:
                print(f"   ⛔ 拒收：{r.reject_reason}")
            elif r.quarantine:
                print("   🚫 检出可疑指令，已隔离，内容不进入上下文")
            else:
                print(f'   <untrusted_external_content source="agent:{r.env.from_agent}">')
                for line in body.splitlines()[:10] or ["（空内容）"]:
                    print(f"   {line}")
                print("   </untrusted_external_content>")
            if r.env.act == "task":
                print(f"   ↳ 回话：a2alink reply {r.env.id} \"...\"")
                print(f"   ↳ 做完：a2alink done {r.env.id}")
            else:
                print(f"   ↳ 要回也可以：a2alink reply {r.env.id} \"...\"")

    # 待办也要顺带说：邀请和投票不会自己冒出来。
    try:
        d = c.pending_actions()
    except LinkError:
        d = {"count": 0}
    if d.get("count"):
        print(f"\n📌 另有 {d['count']} 项待你表态（a2alink pending 查看）")
    return 0


# ------------------------------------------------------------------ peers
def cmd_peers(args: argparse.Namespace) -> int:
    """本机有哪些对话 + 中继上还有谁。"""
    from . import sessions
    try:
        c, ident = _session_client(args)
    except Exception as e:
        print(f"❌ {e}", file=sys.stderr)
        return 2
    st = sessions.SessionStore()
    local = st.all()

    print(f"本机对话（{len(local)} 个）")
    if not local:
        print("  （还没有。在新对话里跑一次 a2alink check 就会自动登记。）")
    for sid, r in sorted(local.items(), key=lambda kv: -float(kv[1].get("last_seen") or 0)):
        mark = "→" if sid == ident.sid else " "
        name = "@" + r["label"] if r.get("label") else "(未命名)"
        print(f" {mark} {name:<12} {r.get('agent_name', ''):<16} "
              f"最后活跃 {_rel(r.get('last_seen'))}")

    ids = {r.get("agent_name") for r in local.values()}
    try:
        remotes = [a for a in c.discover(None, None, 200)
                   if a.get("name") not in ids]
    except LinkError:
        remotes = []
    if remotes:
        print(f"\n中继上的其它 Agent（{len(remotes)} 个，不在本机会话表里）")
        for a in remotes[:30]:
            caps = ",".join(a.get("capabilities") or []) or "-"
            print(f"  · {a['name']:<20} caps={caps}")
    return 0


# ------------------------------------------------------- done / fail / inflight
def cmd_done(args: argparse.Namespace) -> int:
    """标记处理完成。不做这一步，消息就永远挂在 inflight 里。"""
    try:
        c, _ = _session_client(args)
        out = c.done(args.message_id)
    except Exception as e:
        print(f"❌ {e}", file=sys.stderr)
        return 2
    n = out.get("done", 0)
    if not n:
        print("没有可标记的消息（可能已经标过，或这些 ID 不是投给你的）。")
        return 0
    print(f"✅ 已标记 {n} 条为处理完成。")
    return 0


def cmd_fail(args: argparse.Namespace) -> int:
    try:
        c, _ = _session_client(args)
        out = c.fail(args.message_id, reason=args.reason,
                     requeue=not args.no_requeue)
    except Exception as e:
        print(f"❌ {e}", file=sys.stderr)
        return 2
    print(f"已记录失败：第 {out['attempts']}/{out['max_attempts']} 次")
    if out["dead"]:
        print("⛔ 重投次数用尽，这条已进死信队列。")
        print("   查看：a2alink dlq list")
        print(f"   重投：a2alink dlq requeue {args.message_id}")
    elif out["requeued"]:
        print("↻ 已重新投递，下次 check 会再收到它。")
    return 0


def cmd_inflight(args: argparse.Namespace) -> int:
    try:
        c, _ = _session_client(args)
        out = c.inflight(limit=args.limit)
    except Exception as e:
        print(f"❌ {e}", file=sys.stderr)
        return 2
    items = out.get("items", [])
    if not items:
        print("没有挂着的任务，收到的消息都已标记完成。")
        return 0
    print(f"⚠️  {len(items)} 条已读但未标记完成（可能就是掉在地上的任务）：")
    names = _name_map(c)
    for it in items:
        who = names.get(it.get("from_agent")) or it.get("from_agent")
        print(f"  · {it['id']}  来自 {who}  {_rel(it.get('created_at'))}")
        if it.get("attempts"):
            print(f"    失败 {it['attempts']} 次：{it.get('fail_reason') or '-'}")
    print("\n做完用：a2alink done <id>    做不了用：a2alink fail <id> --reason \"...\"")
    return 0


def cmd_dlq(args: argparse.Namespace) -> int:
    try:
        c, _ = _session_client(args)
        if args.action == "list":
            items = c.dlq(limit=args.limit).get("items", [])
            if not items:
                print("死信队列是空的。")
                return 0
            names = _name_map(c)
            print(f"死信 {len(items)} 条（重投次数用尽的消息）：")
            for it in items:
                who = names.get(it.get("from_agent")) or it.get("from_agent")
                print(f"  · {it['id']}  来自 {who}  失败 {it['attempts']} 次")
                print(f"    原因：{it.get('fail_reason') or '-'}")
            print("\n重投：a2alink dlq requeue <id>    清理：a2alink dlq purge <id>")
            return 0
        if args.action == "requeue":
            out = c.dlq_requeue(args.message_id)
            print(f"↻ 已重新投递 {out['message_id']}，下次 check 会收到。")
            return 0
        out = c.dlq_purge(getattr(args, "message_id", "") or "")
        print(f"已清理 {out['purged']} 条死信（只做标记，审计记录不会被删）。")
        return 0
    except Exception as e:
        print(f"❌ {e}", file=sys.stderr)
        return 2


# ------------------------------------------------------------------ will
def cmd_will(args: argparse.Namespace) -> int:
    try:
        c, _ = _session_client(args)
        if args.action == "set":
            out = c.set_will(_resolve_target(args.to), args.text, ttl_seconds=args.ttl)
            print(f"✅ 遗嘱已立：{out['deliver_after']} 秒没动静就发给 {args.to}")
            print("   中继只能转交这封已签名的信；内容在本地加密，它自己读不到。")
            print("   撤销：a2alink will clear")
            return 0
        if args.action == "clear":
            c.clear_will()
            print("✅ 遗嘱已撤销。")
            return 0
        info = c.will_info()
        if not info.get("will"):
            print("当前没有遗嘱。")
            print('  立一个：a2alink will set @某人 "我掉线了，手上的任务没做完" --ttl 600')
            return 0
        state = "已触发" if info.get("fired") else "待触发"
        to_id = str(info.get("to") or "")
        to_show = _name_map(c).get(to_id) or to_id
        print(f"遗嘱{state}：{int(info['ttl_seconds'])} 秒无动静后发给 {to_show}")
        print(f"  消息 ID：{info.get('message_id')}")
        return 0
    except Exception as e:
        print(f"❌ {e}", file=sys.stderr)
        return 2


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
    p.add_argument("--as", dest="as_", default=None, metavar="别名",
                   help="以指定会话身份执行（会话别名或会话 ID）")
    sub = p.add_subparsers(dest="cmd", required=True)

    # ---------------- v0.3：会话 / 一键装 / 跨对话 ----------------
    se = sub.add_parser("session", help="会话身份：我是谁 / 给对话起名 / 列本机对话")
    ses = se.add_subparsers(dest="action", required=True)
    ses.add_parser("whoami", help="当前对话的身份").set_defaults(func=cmd_session)
    sname = ses.add_parser("name", help="给当前对话起名，之后别人可以 @这个名字")
    sname.add_argument("label")
    sname.set_defaults(func=cmd_session)
    srel = ses.add_parser("release", help="释放一个别名")
    srel.add_argument("label")
    srel.set_defaults(func=cmd_session)
    ses.add_parser("list", help="本机所有对话").set_defaults(func=cmd_session)
    sfg = ses.add_parser("forget", help="从会话表移除（默认不删身份文件）")
    sfg.add_argument("who", nargs="?", default=None)
    sfg.add_argument("--drop-files", dest="drop_files", action="store_true",
                     help="同时删除身份目录（私钥与审计链会一起消失）")
    sfg.add_argument("--yes", action="store_true")
    sfg.set_defaults(func=cmd_session)

    sk = sub.add_parser("skill", help="装成 WorkBuddy/Claude 技能（一键安装）")
    sks = sk.add_subparsers(dest="action", required=True)
    ski = sks.add_parser("install", help="安装到 ~/.workbuddy/skills/a2alink")
    ski.add_argument("--dir", default=None, help="技能根目录（默认 ~/.workbuddy/skills）")
    ski.add_argument("--force", action="store_true", help="覆盖不是本工具装的同名目录")
    ski.add_argument("--dry-run", dest="dry_run", action="store_true",
                     help="只列要写哪些文件，不落盘")
    ski.set_defaults(func=cmd_skill)
    sst = sks.add_parser("status", help="装了没 / 版本对不对 / 源码还在不在")
    sst.add_argument("--dir", default=None)
    sst.set_defaults(func=cmd_skill)
    sun = sks.add_parser("uninstall", help="卸载技能（不动身份与审计）")
    sun.add_argument("--dir", default=None)
    sun.add_argument("--force", action="store_true")
    sun.set_defaults(func=cmd_skill)

    u = sub.add_parser("up", help="确保本地中继在跑（不在就拉起来）")
    u.add_argument("--no-mesh", dest="no_mesh", action="store_true",
                   help="关闭同机会话互信（默认开启）")
    u.add_argument("--will", dest="will_text", default="",
                   help="立遗嘱：掉线时替你发出去的那句话")
    u.add_argument("--will-to", dest="will_to", default="",
                   help="遗嘱发给谁（@名字），不给就不立")
    u.add_argument("--will-ttl", dest="will_ttl", type=int, default=600,
                   help="多少秒无动静算掉线（默认 600）")
    u.set_defaults(func=cmd_up)
    dw = sub.add_parser("down", help="停掉本工具拉起的本地中继")
    dw.add_argument("--keep-will", dest="keep_will", action="store_true",
                    help="保留遗嘱（默认正常下线会撤销，避免误发）")
    dw.set_defaults(func=cmd_down)

    sy = sub.add_parser("say", help="给某个对话发消息（不等回复）")
    sy.add_argument("to", help="会话别名(@运维)、agent 名或 agent_id")
    sy.add_argument("text", nargs="?", default=None)
    sy.add_argument("--json", default=None)
    sy.add_argument("--act", default="event",
                    choices=["event", "task", "result", "chat", "notice"])
    sy.add_argument("--stage", default="open",
                    choices=["open", "done", "handoff", "need_human", "blocked"])
    sy.add_argument("--conversation", default=None)
    sy.add_argument("--force", action="store_true")
    sy.add_argument("--reason", default="")
    sy.set_defaults(func=cmd_say)

    aq = sub.add_parser("ask", help="提问并等回答（等不到就说等不到，不重试）")
    aq.add_argument("to")
    aq.add_argument("text")
    aq.add_argument("--wait", type=float, default=15.0,
                    help="最多等多少秒，0 表示投递即返回")
    aq.add_argument("--conversation", default=None)
    aq.add_argument("--force", action="store_true")
    aq.add_argument("--reason", default="")
    aq.set_defaults(func=cmd_ask)

    rp = sub.add_parser("reply", help="回复某条消息（回复后这条链结束）")
    rp.add_argument("msg_id")
    rp.add_argument("text")
    rp.add_argument("--to", default=None)
    rp.set_defaults(func=cmd_reply)

    ck = sub.add_parser("check", help="收信 + 摘要（通信前先跑这个）")
    ck.add_argument("--wait", type=float, default=0.0)
    ck.add_argument("--limit", type=int, default=20)
    ck.set_defaults(func=cmd_check)

    sub.add_parser("peers", help="本机有哪些对话、中继上还有谁").set_defaults(
        func=cmd_peers)

    dn = sub.add_parser("done", help="标记消息已处理完（和「已读」不是一回事）")
    dn.add_argument("message_id", nargs="+", help="一个或多个消息 ID")
    dn.set_defaults(func=cmd_done)

    fl = sub.add_parser("fail", help="上报处理失败：默认重投，超次数进死信")
    fl.add_argument("message_id")
    fl.add_argument("--reason", default="", help="失败原因，会写进审计")
    fl.add_argument("--no-requeue", action="store_true", help="不重投，只记一次失败")
    fl.set_defaults(func=cmd_fail)

    inf = sub.add_parser("inflight", help="已读但没标完成的消息（可能掉地上的任务）")
    inf.add_argument("--limit", type=int, default=50)
    inf.set_defaults(func=cmd_inflight)

    dq = sub.add_parser("dlq", help="死信队列：查看 / 重投 / 清理")
    dqs = dq.add_subparsers(dest="action", required=True)
    ql = dqs.add_parser("list", help="列出死信")
    ql.add_argument("--limit", type=int, default=50)
    ql.set_defaults(func=cmd_dlq)
    qr = dqs.add_parser("requeue", help="重新投递一条死信")
    qr.add_argument("message_id")
    qr.set_defaults(func=cmd_dlq)
    qp = dqs.add_parser("purge", help="清理死信（只标记，不删审计）")
    qp.add_argument("message_id", nargs="?", default="")
    qp.set_defaults(func=cmd_dlq)

    wl = sub.add_parser("will", help="遗嘱：我掉线了，替我把这句话发出去")
    wls = wl.add_subparsers(dest="action", required=True)
    wset = wls.add_parser("set", help="立遗嘱（中继保管的是已签名信封）")
    wset.add_argument("to", help="掉线后通知谁")
    wset.add_argument("text", help="要说的内容")
    wset.add_argument("--ttl", type=int, default=600,
                      help="多少秒没动静算掉线（默认 600）")
    wset.set_defaults(func=cmd_will)
    wls.add_parser("show", help="查看当前遗嘱").set_defaults(func=cmd_will)
    wls.add_parser("clear", help="撤销遗嘱").set_defaults(func=cmd_will)

    r = sub.add_parser("registry", help="启动注册中心")
    r.add_argument("--db", default="a2alink.sqlite3")
    r.add_argument("--host", default="127.0.0.1")
    r.add_argument("--port", type=int, default=8787)
    r.add_argument("--invite-code", default=None, help="非空时注册必须提供邀请码")
    r.add_argument("--local-mesh", action="store_true",
                   help="同机会话免好友审批（仅监听回环地址时生效，每次放行都写审计）")
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

    kp = sub.add_parser("keys", help="密钥与公钥固定（指纹/上传/轮换/pin）")
    kss = kp.add_subparsers(dest="action", required=True)
    kss.add_parser("show", help="查看本机公钥指纹（离线）")
    kss.add_parser("list", help="列出已固定的对端公钥（离线）")
    kw = kss.add_parser("forget", help="删除某条固定记录（离线）")
    kw.add_argument("who")
    kw.add_argument("--yes", action="store_true")
    kp1 = kss.add_parser("publish", help="把本机公钥登记到注册中心")
    kp1.add_argument("--reason", default="")
    kr = kss.add_parser("rotate", help="轮换密钥对（会断开所有对端的信任）")
    kr.add_argument("--yes", action="store_true")
    kq = kss.add_parser("peer", help="查对端公钥指纹（来自注册中心，未核对）")
    kq.add_argument("who")
    kn = kss.add_parser("pin", help="固定对端公钥（带外核对后使用）")
    kn.add_argument("who")
    kn.add_argument("--expect", default="", help="你从其他渠道拿到的指纹，必须一致")
    kn.add_argument("--note", default="", help="备注：从哪个渠道核对的")
    kn.add_argument("--yes", action="store_true")
    for _p_ in (kp1, kr, kq, kn):
        _p_.add_argument("--trust-policy", default="tofu",
                         choices=["tofu", "strict", "off"])
    for _p_ in (kss.choices["show"], kss.choices["list"], kss.choices["forget"]):
        _p_.add_argument("--trust-policy", default="tofu",
                         choices=["tofu", "strict", "off"])
    kp.set_defaults(func=cmd_keys)

    sub.add_parser("doctor", help="上线前自检").set_defaults(func=cmd_doctor)

    sub.add_parser("demo", help="30 秒演示").set_defaults(func=cmd_demo)
    return p


_GLOBAL_WITH_VALUE = ("--as", "--registry", "--home", "--scope", "--name", "--cap")


def _hoist_global(argv: List[str]) -> List[str]:
    """把全局选项从子命令后面提到最前面。

    argparse 要求全局选项写在子命令之前，但没人会记得这个规则。真实的
    写法几乎总是 ``a2alink say @运维 "..." --as 运维``，不处理的话用户只会
    看到 "unrecognized arguments"，然后以为工具坏了。

    与其在每个子 parser 上再注册一遍（argparse 会用子 parser 的 default
    把父级已解析的值覆盖掉，是个经典坑），不如在解析前挪一下位置。
    """
    head: List[str] = []
    rest: List[str] = []
    i = 0
    while i < len(argv):
        a = argv[i]
        hit = next((g for g in _GLOBAL_WITH_VALUE
                    if a == g or a.startswith(g + "=")), None)
        if hit:
            if "=" in a:
                head.append(a)
                i += 1
            elif i + 1 < len(argv):
                head.extend([a, argv[i + 1]])
                i += 2
            else:
                rest.append(a)
                i += 1
            continue
        rest.append(a)
        i += 1
    return head + rest


def main(argv: Optional[List[str]] = None) -> int:
    raw = list(sys.argv[1:] if argv is None else argv)
    args = build_parser().parse_args(_hoist_global(raw))
    # 时间窗口换算成绝对时间戳，供审计查询使用
    hours = float(getattr(args, "hours", 24) or 0)
    args.since_s = 0.0 if hours <= 0 else time.time() - hours * 3600
    # guard / logs 不需要身份，提前分发，避免因连不上注册中心而失败。
    # 这条很重要：出问题的时候注册中心往往正好连不上，查日志不能被它拖住。
    if args.cmd in ("guard", "logs"):
        return args.func(args)
    # 密钥的离线命令同理：查指纹、看信任列表不该要求注册中心在线。
    if args.cmd == "keys" and getattr(args, "action", "") in ("show", "list", "forget"):
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
