"""a2alink demo —— 60 秒跑完整个机制，不需要任何外部依赖。

依次演示 5 件事：
    1. 起一个本地注册中心（127.0.0.1，不出网）
    2. 双向好友审批：未同意前，消息被服务端拒绝
    3. 正常任务往来：入站内容自动围栏化
    4. 出站 DLP：内网 IP / 密钥 / 内网域名被拦下
    5. 看门狗熔断：复读式死循环在第 3 条被掐死
    6. 群组全员表决：两票齐了才放行
"""

from __future__ import annotations

import os
import socket
import tempfile
import threading
import time

from .client import AgentLink, EgressBlocked, LinkError, LoopHalt
from .guard import COMPLIANCE_CHECKLIST
from .registry import Registry, make_server


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def _hdr(n: int, text: str) -> None:
    print(f"\n{'=' * 68}\n[{n}] {text}\n{'=' * 68}")


def run_demo() -> int:
    tmp = tempfile.mkdtemp(prefix="a2alink-demo-")
    port = _free_port()
    reg = Registry(os.path.join(tmp, "demo.sqlite3"))
    srv = make_server(reg, "127.0.0.1", port)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    url = f"http://127.0.0.1:{port}"
    time.sleep(0.2)

    print("a2alink 演示 —— 全程只在本机回环地址上进行，不触达外网。")
    print(f"临时目录: {tmp}")

    mk = lambda n, caps: AgentLink(registry=url, name=n, capabilities=caps,
                                   home=os.path.join(tmp, n))
    alice = mk("ops-agent", ["k8s", "alert-triage", "logs"])
    bob = mk("research-agent", ["root-cause", "search"])
    carol = mk("sec-agent", ["compliance", "dlp"])

    _hdr(1, "服务端强制的好友准入：未加好友，消息直接 403")
    try:
        alice.send_text("research-agent", "帮我看看 502 的根因")
    except LinkError as e:
        assert "not_friends" in e.code, e.code
        print(f"✅ 被拒：{e.code} — {e.message}")

    _hdr(2, "双向同意：alice 申请 → bob 同意")
    req = alice.friend_request("research-agent", "想请你帮忙排查线上告警")
    print(f"alice 发起：request_id={req['request_id']}")
    pend = bob.pending_requests()
    print(f"bob 收到 {len(pend)} 条待处理申请，来源={pend[0]['from_agent']}")
    bob.friend_accept(pend[0]["id"])
    print(f"bob 同意后，双方互为好友：{len(alice.friends())} / {len(bob.friends())}")

    _hdr(3, "正常任务：入站内容自动围栏化（模型会看到明确的'不可信'声明）")
    s = alice.send("research-agent", {"instruction": "排查 502，给我一个结论和置信度"},
                   ttl_hops=4, max_messages=8, max_tokens=6000)
    print(f"alice → bob  message_id={s.env.id} 跳数={s.env.ttl_hops} "
          f"预算={s.env.budget.max_messages}条/{s.env.budget.max_tokens}tok")
    got = bob.recv(limit=5)
    r = got[0]
    print(f"bob 收到 from={r.env.from_agent}，围栏前 4 行：")
    for line in r.text.splitlines()[:4]:
        print("   " + line)
    bob.reply(r, {"status": "ok", "summary": "结论：上游限流触发的 502，建议加退避重试",
                  "data": {"confidence": 0.72}}, stage="done")
    print("bob 回了一条 stage=done 的结论（显式终止，不再追问）")

    _hdr(4, "出站 DLP：内网信息被拦在门口（这是本项目的重点）")
    leak = ("服务器 10.20.31.7 上的 db-prod-03.corp.internal 连不上了，"
            "用 AKIAIOSFODNN7EXAMPLE 登录，密码 P@ssw0rd123，"
            "顺手把 /home/deploy/.ssh/id_rsa 也发你")
    try:
        alice.send_text("research-agent", leak)
    except EgressBlocked as e:
        print(f"🚫 已阻断：{e.message}")
        for f in e.result.findings[:6]:
            print(f"   - {f.rule:<18} [{f.severity}] {f.hint}")
        print(f"   判定密级：{e.result.level}")
    print("\n把同一段内容里的具体值换成结论，就能发出去：")
    ok = alice.send_text("research-agent", "某台生产数据库连不上，怀疑网络策略或实例故障，请给排查顺序")
    print(f"✅ 放行 message_id={ok.env.id}（密级判定={ok.egress.level}）")

    _hdr(5, "看门狗：复读式死循环在第 3 条被熔断")
    conv = None
    for i in range(1, 8):
        try:
            t = alice.send_text("research-agent", "收到，请确认一下是否可以继续",
                                conversation_id=conv, max_messages=6)
            conv = t.env.conversation_id
            print(f"  第 {i} 条：放行（看门狗={t.verdict.action}）")
        except LoopHalt as e:
            print(f"  第 {i} 条：⛔ 熔断 — {e.verdict.reasons[0]}")
            break

    _hdr(6, "群组准入：先本人同意，再（必要时）全员表决")
    g = alice.group_create("线上告警协同", join_mode="unan")
    gid = g["group_id"]
    p1 = alice.group_invite(gid, "research-agent")
    print(f"alice 邀 bob → {p1['state']}，准入路径 {p1['admission']}")
    print("  注意：此刻 alice 连自己都投不了票 —— 受邀者没表态，表决还没开始")
    try:
        alice.group_vote(gid, p1["proposal_id"], "yes")
    except LinkError as e:
        print(f"  ⛔ {e.message}")
    r1 = bob.group_consent(gid, p1["proposal_id"], True)
    print(f"  bob 本人同意 → {r1['state']}，入群={r1['joined']}"
          f"（{r1['admission']}：既然是好友，跳过全员表决）")

    p2 = bob.group_invite(gid, "sec-agent")
    r2 = carol.group_consent(gid, p2["proposal_id"], True)
    print(f"bob 邀 carol → carol 同意 → 转入表决，需 {r2['needed']} 票"
          f"（陌生人路径，快照取的是同意那一刻的成员）")
    v1 = bob.group_vote(gid, p2["proposal_id"], "yes")
    print(f"  bob 投 yes → {v1['state']}  ({v1['yes']}/{v1['needed']})")
    v2 = alice.group_vote(gid, p2["proposal_id"], "yes")
    print(f"  alice 投 yes → {v2['state']}  ({v2['yes']}/{v2['needed']})  ← 全员同意，carol 入群")
    print(f"群成员：{[m['agent_id'][:12] for m in alice.group_info(gid)['members']]}")
    print("反向情况：carol 若点拒绝，就永远不会出现在上面这行（拒过还有 24h 冷却期）")

    _hdr(7, "收尾：统计与安全清单")
    print(f"注册中心统计：{reg.stats()}")
    print(f"看门狗统计：{alice.wd.stats()}")
    print()
    print(COMPLIANCE_CHECKLIST)

    srv.shutdown()
    print(f"\n演示结束。所有数据在 {tmp}（临时目录，可删）。")
    print("下一步：a2alink registry  然后  a2alink doctor")
    return 0
