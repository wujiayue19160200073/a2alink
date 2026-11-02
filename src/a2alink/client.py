"""A2A Link 客户端 SDK。

========================= 设计原则 =========================
1) 闸门内置，不靠自觉
   send() 内部强制走 EgressGuard + Watchdog；recv() 内部强制走 IngressGuard。
   没有"可选跳过"参数，除非显式传 force=True 并留下审计记录。
   理由：安全机制一旦变成"建议开启"，上线三个月后它一定被关掉。

2) 身份落在本地，token 不外泄
   ~/.a2alink/<agent>/identity.json，权限 600。token 只在注册时返回一次。

3) 不可信内容默认进围栏
   recv() 返回的 text 已经被 <untrusted_external_content> 包裹并附了系统声明，
   直接塞进 prompt 是相对安全的；如果你手动拆开用，风险自负。

⚠️⚠️⚠️  重要安全提醒（请连同 README 一起读）  ⚠️⚠️⚠️
本 SDK 连接的是**公网上的其他 Agent**，不是你的内网服务。
任何一次 send() 都是数据出域行为。默认策略是"发往外网"（peer_scope=wan），
会把内网 IP、内部域名、主机名、手机号、身份证、密钥、连接串全部拦下。
但这道闸是**正则 + 熵检测**，它挡不住：
    · 结构化敏感数据（客户名单、财务明细、工单原文、代码逻辑）
    · 语义层面的泄密（"我们下季度主推的那个还没发布的型号"）
    · 你自己主动写进 payload 的业务内容
所以：**闸门是最后一道网，不是免责条款。** 出域前必须过人审 + 合规脱敏。
"""

from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple

from .abuse import PropagationBlocked, PropagationGuard, ProvenanceError
from .guard import (ALLOW, BLOCK, EgressGuard, GuardResult, IngressGuard,
                    SCOPE_LAN, SCOPE_LOCAL, SCOPE_WAN, LEVEL_ORDER)
from .protocol import (ACT_NOTICE, ACT_RESULT, ACT_TASK, Budget, Envelope,
                       STAGE_DONE, TERMINAL_STAGES, make_task, new_id)
from .watchdog import DEGRADE, PASS, STOP, Verdict, Watchdog


class LinkError(Exception):
    def __init__(self, code: str, message: str, status: int = 0) -> None:
        super().__init__(f"[{code}] {message}")
        self.code = code
        self.message = message
        self.status = status


class EgressBlocked(LinkError):
    """出站被 DLP 拦下。必须由人确认后才能 force=True 重发。"""

    def __init__(self, result: GuardResult) -> None:
        super().__init__("egress_blocked",
                         "出站内容未通过安全闸门：" + "; ".join(result.reasons or ["命中敏感信息"]))
        self.result = result


class LoopHalt(LinkError):
    """被看门狗熔断。这不是错误，是治理层在保护你的钱包。"""

    def __init__(self, verdict: Verdict) -> None:
        super().__init__("loop_halt", "会话被熔断：" + "; ".join(verdict.reasons))
        self.verdict = verdict


@dataclass
class Sent:
    env: Envelope
    delivered_to: int = 0
    duplicate: bool = False
    egress: Optional[GuardResult] = None
    verdict: Optional[Verdict] = None
    seq: int = 0


@dataclass
class Received:
    env: Envelope
    seq: int = 0
    ingress: Optional[GuardResult] = None
    verdict: Optional[Verdict] = None
    text: str = ""          # 已围栏化的安全文本
    quarantine: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {"envelope": self.env.to_dict(), "text": self.text,
                "quarantine": self.quarantine,
                "ingress": self.ingress.to_dict() if self.ingress else None,
                "verdict": self.verdict.to_dict() if self.verdict else None}


class AgentLink:
    """一个 Agent 的通信端点。通常一个进程一个实例。"""

    def __init__(self, registry: str = "http://127.0.0.1:8787",
                 name: Optional[str] = None,
                 capabilities: Optional[List[str]] = None,
                 description: str = "",
                 home: Optional[str] = None,
                 peer_scope: str = SCOPE_WAN,
                 peer_scopes: Optional[Dict[str, str]] = None,
                 deny_terms: Optional[List[str]] = None,
                 allow_terms: Optional[List[str]] = None,
                 watchdog: Optional[Watchdog] = None,
                 invite_code: Optional[str] = None,
                 auto_register: bool = True,
                 timeout: float = 15.0,
                 propagation: Optional[PropagationGuard] = None,
                 allow_forward: bool = False) -> None:
        self.registry = registry.rstrip("/")
        self.name = name or f"agent-{new_id()[:6]}"
        self.capabilities = capabilities or []
        self.description = description
        self.home = home or os.path.join(
            os.path.expanduser("~"), ".a2alink", self._safe(self.name))
        self.timeout = timeout
        self.peer_scope = peer_scope
        self.peer_scopes = dict(peer_scopes or {})
        self.wd = watchdog or Watchdog()
        self.egress = EgressGuard(scope=peer_scope, deny_terms=deny_terms,
                                  allow_terms=allow_terms)
        self.ingress = IngressGuard()
        # 扩散保险丝：默认开启，转发默认关闭。这两条是"协议不被拿去作恶"的底线。
        self.propagation = propagation or PropagationGuard(allow_forward=allow_forward)
        self.invite_code = invite_code
        self._cursor = 0
        self.agent_id = ""
        self.token = ""
        self._load_or_register(auto_register)

    # ------------------------------------------------------------------
    # 身份
    # ------------------------------------------------------------------
    @staticmethod
    def _safe(s: str) -> str:
        return "".join(c for c in s if c.isalnum() or c in "-_")[:40] or "default"

    @property
    def _id_path(self) -> str:
        return os.path.join(self.home, "identity.json")

    def _load_or_register(self, auto_register: bool) -> None:
        os.makedirs(self.home, exist_ok=True)
        if os.path.exists(self._id_path):
            try:
                with open(self._id_path, "r", encoding="utf-8") as f:
                    d = json.load(f)
                if d.get("registry", "").rstrip("/") == self.registry:
                    self.agent_id, self.token = d["agent_id"], d["token"]
                    self.name = d.get("name", self.name)
                    self._cursor = int(d.get("cursor", 0))
                    return
            except (OSError, ValueError, KeyError):
                pass
        if not auto_register:
            raise LinkError("no_identity", "本地没有身份文件，且未开启自动注册")
        out = self._api("POST", "/v1/agents/register", {
            "name": self.name, "capabilities": self.capabilities,
            "description": self.description, "invite_code": self.invite_code,
        }, auth=False)
        self.agent_id, self.token = out["agent_id"], out["token"]
        self.name = out.get("name", self.name)
        self._save_identity()
        if not os.environ.get("A2ALINK_QUIET"):
            print(f"[a2alink] 已注册身份 {self.name} ({self.agent_id})")
            print(f"[a2alink] 身份文件: {self._id_path}（含 token，权限 600，请勿提交仓库）")

    def _save_identity(self) -> None:
        os.makedirs(self.home, exist_ok=True)
        tmp = self._id_path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump({"agent_id": self.agent_id, "token": self.token,
                       "name": self.name, "registry": self.registry,
                       "cursor": self._cursor}, f, ensure_ascii=False, indent=2)
        try:
            os.chmod(tmp, 0o600)
        except OSError:
            pass
        os.replace(tmp, self._id_path)

    # ------------------------------------------------------------------
    # HTTP
    # ------------------------------------------------------------------
    def _api(self, method: str, path: str, body: Optional[Dict[str, Any]] = None,
             auth: bool = True, qs: Optional[str] = None) -> Dict[str, Any]:
        url = self.registry + path + (f"?{qs}" if qs else "")
        data = json.dumps(body, ensure_ascii=False).encode("utf-8") if body is not None else None
        req = urllib.request.Request(url, data=data, method=method)
        req.add_header("Content-Type", "application/json; charset=utf-8")
        if auth and self.token:
            req.add_header("Authorization", f"Bearer {self.token}")
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as r:
                raw = r.read().decode("utf-8")
                return json.loads(raw) if raw else {}
        except urllib.error.HTTPError as e:
            raw = e.read().decode("utf-8", "replace")
            try:
                err = json.loads(raw).get("error", {})
            except json.JSONDecodeError:
                err = {"code": "http_error", "message": raw[:300]}
            raise LinkError(err.get("code", "http_error"),
                            err.get("message", str(e)), e.code) from e
        except urllib.error.URLError as e:
            raise LinkError("network", f"连不上注册中心 {self.registry}: {e.reason}") from e

    # ------------------------------------------------------------------
    # 控制面
    # ------------------------------------------------------------------
    def me(self) -> Dict[str, Any]:
        return self._api("GET", f"/v1/agents/{self.agent_id}")

    def discover(self, capability: Optional[str] = None, q: Optional[str] = None,
                 limit: int = 50) -> List[Dict[str, Any]]:
        parts = []
        if capability:
            parts.append("capability=" + urllib.parse.quote(capability))
        if q:
            parts.append("q=" + urllib.parse.quote(q))
        parts.append(f"limit={limit}")
        return self._api("GET", "/v1/agents", qs="&".join(parts)).get("agents", [])

    def resolve(self, who: str) -> str:
        """允许用名字，也允许用 agent_id。名字优先精确匹配。"""
        if who.startswith("agt-"):
            return who
        for a in self.discover(q=who, limit=20):
            if a["name"] == who:
                return a["agent_id"]
        raise LinkError("not_found", f"找不到名为 {who!r} 的 Agent")

    def friend_request(self, who: str, message: str = "") -> Dict[str, Any]:
        return self._api("POST", "/v1/friends/requests",
                         {"to": self.resolve(who), "message": message})

    def friend_accept(self, request_id: str) -> Dict[str, Any]:
        return self._api("POST", f"/v1/friends/requests/{request_id}/respond",
                         {"accept": True})

    def friend_reject(self, request_id: str) -> Dict[str, Any]:
        return self._api("POST", f"/v1/friends/requests/{request_id}/respond",
                         {"accept": False})

    def pending_requests(self, box: str = "in") -> List[Dict[str, Any]]:
        return self._api("GET", "/v1/friends/requests", qs=f"box={box}").get("requests", [])

    def friends(self) -> List[Dict[str, Any]]:
        return self._api("GET", "/v1/friends").get("friends", [])

    def unfriend(self, who: str) -> Dict[str, Any]:
        return self._api("DELETE", f"/v1/friends/{self.resolve(who)}")

    def group_create(self, name: str, join_mode: str = "unan", quorum: float = 0.0,
                     proposal_ttl: float = 86400, max_members: int = 50,
                     on_timeout: str = "reject", trusted_direct: bool = True,
                     consent_ttl: float = 259200,
                     invite_per_hour: int = 20) -> Dict[str, Any]:
        return self._api("POST", "/v1/groups", {
            "name": name, "join_mode": join_mode, "quorum": quorum,
            "proposal_ttl": proposal_ttl, "max_members": max_members,
            "on_timeout": on_timeout, "trusted_direct": bool(trusted_direct),
            "consent_ttl": consent_ttl, "invite_per_hour": invite_per_hour})

    def group_info(self, gid: str) -> Dict[str, Any]:
        return self._api("GET", f"/v1/groups/{gid}")

    def group_invite(self, gid: str, who: str) -> Dict[str, Any]:
        return self._api("POST", f"/v1/groups/{gid}/invite", {"agent_id": self.resolve(who)})

    def group_vote(self, gid: str, proposal_id: str, vote: str) -> Dict[str, Any]:
        return self._api("POST", f"/v1/groups/{gid}/vote",
                         {"proposal_id": proposal_id, "vote": vote})

    def group_proposals(self, gid: str) -> List[Dict[str, Any]]:
        return self._api("GET", f"/v1/groups/{gid}/proposals").get("proposals", [])

    def group_remove(self, gid: str, who: str) -> Dict[str, Any]:
        return self._api("POST", f"/v1/groups/{gid}/remove", {"agent_id": self.resolve(who)})

    def group_consent(self, gid: str, proposal_id: str, accept: bool,
                      reason: str = "") -> Dict[str, Any]:
        """受邀者对"被拉进群"表态。**这一步不可跳过** —— 不同意就永远不进群。

        这是硬约束，不留开关：被人拉进群这件事本身就能被当作骚扰和监看的载体，
        "默认同意"是很多 IM 的历史包袱，这里不背。
        """
        return self._api("POST", f"/v1/groups/{gid}/consent",
                         {"proposal_id": proposal_id, "accept": bool(accept),
                          "reason": str(reason)[:300]})

    def pending_actions(self) -> Dict[str, Any]:
        """我这边待处理的事：待我表态的入群邀请 + 待我投的表决票。

        给人和 Agent 共用同一份数据——人看的是可视化面板，Agent 看的是这个接口。
        """
        return self._api("GET", "/v1/pending")

    # ------------------------------------------------------------------
    # 数据面：发送（内置出站闸门 + 看门狗）
    # ------------------------------------------------------------------
    def _scope_for(self, peer: str) -> str:
        """对端信任域。未显式配置的一律当公网（wan）——这是安全的默认值。"""
        return self.peer_scopes.get(peer, self.peer_scope)

    def send(self, to: str, payload: Dict[str, Any], act: str = ACT_TASK,
             stage: str = "open", conversation_id: Optional[str] = None,
             ttl_hops: int = 4, ttl_seconds: int = 600,
             max_messages: int = 12, max_tokens: int = 12000,
             capabilities: Optional[List[str]] = None,
             force: bool = False, in_reply_to: Optional[str] = None,
             forwarded_from: Optional[str] = None) -> Sent:
        """发一条信封。内部顺序：DLP → 扩散保险丝 → 看门狗 → 网络。任何一步不过就不发。

        force=True 只应在人明确确认"这段可以发"之后使用，并且会写审计日志。
        forwarded_from 非空表示"这是别人的话"，默认会被直接拒绝（见 abuse.py）。
        """
        peer = to if to.startswith(("agt-", "grp-")) else self.resolve(to)
        is_group = peer.startswith("grp-")
        scope = SCOPE_LAN if is_group else self._scope_for(peer)
        self.egress.scope = scope

        egress, clean_payload = self.egress.check_payload(payload)
        if egress.action == BLOCK and not force:
            raise EgressBlocked(egress)

        # 转发闸门：默认关闭。要开必须显式 allow_forward=True，且强制署名来源。
        if forwarded_from:
            self.propagation.check_forward(forwarded_from)
            clean_payload = dict(clean_payload)
            clean_payload["_provenance"] = {"forwarded_from": forwarded_from,
                                            "stated_by": self.agent_id,
                                            "note": "本条为转发，非说话人原创"}
        conv = conversation_id or new_id("conv-")
        try:
            self.propagation.check(
                json.dumps(clean_payload, ensure_ascii=False, sort_keys=True), conv, peer)
        except PropagationBlocked:
            if not force:
                raise

        now = time.time()
        env = Envelope(
            id=new_id(),
            from_agent=self.agent_id,
            to_type="group" if is_group else "agent",
            to_id=peer,
            act=act,
            stage=stage,
            payload=clean_payload,
            conversation_id=conv,
            in_reply_to=in_reply_to,
            idempotency_key=new_id("idem-"),
            created_at=now,
            expires_at=now + max(1, ttl_seconds),
            ttl_hops=max(0, min(ttl_hops, 16)),
            budget=Budget(max_messages=max_messages, max_tokens=max_tokens),
            capabilities=list(capabilities or []),
            trace_id=new_id("trace-"),
        )

        verdict = self.wd.check_outbound(env)
        if verdict.action == STOP and not force:
            raise LoopHalt(verdict)

        out = self._api("POST", "/v1/messages", {"envelope": env.to_dict()})
        return Sent(env=env, delivered_to=out.get("delivered_to", 0),
                    duplicate=out.get("duplicate", False), egress=egress,
                    verdict=verdict, seq=out.get("seq", 0))

    def send_text(self, to: str, text: str, act: str = ACT_TASK,
                  stage: str = "open", **kw: Any) -> Sent:
        return self.send(to, {"instruction": text}, act=act, stage=stage, **kw)

    def reply(self, received: "Received", payload: Dict[str, Any],
              stage: str = STAGE_DONE, act: str = ACT_RESULT) -> Sent:
        """标准回信：继承会话、递减 TTL、把预算用量还回去。"""
        env = received.env
        child = env.reply(self.agent_id, payload, act=act, stage=stage)
        egress, clean = self.egress.check_payload(payload)
        if egress.action == BLOCK:
            raise EgressBlocked(egress)
        child.payload = clean
        # 回信也要过扩散保险丝：否则"先试探一次，然后靠自动回复扩散"就成了绕过口。
        self.propagation.check(
            json.dumps(clean, ensure_ascii=False, sort_keys=True),
            child.conversation_id, child.to_id)
        verdict = self.wd.check_outbound(child)
        if verdict.action == STOP:
            raise LoopHalt(verdict)
        out = self._api("POST", "/v1/messages", {"envelope": child.to_dict()})
        return Sent(env=child, delivered_to=out.get("delivered_to", 0),
                    egress=egress, verdict=verdict, seq=out.get("seq", 0))

    # ------------------------------------------------------------------
    # 数据面：接收（内置入站闸门 + 看门狗）
    # ------------------------------------------------------------------
    def recv(self, wait: float = 0.0, limit: int = 20, auto_ack: bool = True) -> List[Received]:
        raw = self._api("GET", "/v1/inbox",
                        qs=f"cursor={self._cursor}&limit={limit}&wait={wait}")
        out: List[Received] = []
        for d in raw.get("items", []):
            seq = int(d.pop("_seq", 0))
            try:
                env = Envelope.from_dict(d)
            except Exception:
                continue    # 畸形信封直接丢弃，不进入上下文

            verdict = self.wd.check_inbound(env)
            if verdict.action == STOP:
                out.append(Received(env=env, seq=seq, verdict=verdict,
                                    text="", quarantine=False))
                self._cursor = max(self._cursor, seq)
                continue

            # 群消息加一个来源标签；单聊不需要
            source = f"agent:{env.from_agent}"
            if env.to_type == "group":
                source += f"@group:{env.to_id}"
            ing, fenced = self.ingress.check_and_fence(env.payload_text(), source)
            out.append(Received(env=env, seq=seq, ingress=ing, verdict=verdict,
                                text=fenced if ing.ok else "",
                                quarantine=not ing.ok))
            self._cursor = max(self._cursor, seq)

        if auto_ack and self._cursor:
            try:
                self._api("POST", "/v1/inbox/ack", {"cursor": self._cursor})
                self._save_identity()
            except LinkError:
                pass
        return out

    def ack(self, cursor: Optional[int] = None) -> Dict[str, Any]:
        return self._api("POST", "/v1/inbox/ack", {"cursor": cursor or self._cursor})

    # ------------------------------------------------------------------
    # 主循环
    # ------------------------------------------------------------------
    def run(self, handler: Callable[["AgentLink", Received], Optional[Dict[str, Any]]],
            poll: float = 1.0, max_rounds: int = 200,
            on_halt: Optional[Callable[[Received], None]] = None) -> Dict[str, int]:
        """收 -> 处理 -> 回。handler 返回 dict 则自动回信（默认 stage=done）。

        handler 里可以做任何事，但**不要**自己再调用 send 去追问对方，
        一句话一轮就够了。追问是循环的起点。
        """
        handled = replied = halted = 0
        for _ in range(max_rounds):
            batch = self.recv(wait=poll)
            if not batch:
                break
            for r in batch:
                if r.verdict and r.verdict.action == STOP:
                    halted += 1
                    if on_halt:
                        on_halt(r)
                    continue
                if r.quarantine:
                    handled += 1
                    continue
                try:
                    res = handler(self, r)
                except LoopHalt:
                    halted += 1
                    continue
                handled += 1
                if res is not None:
                    stage = res.pop("_stage", STAGE_DONE)
                    try:
                        self.reply(r, res, stage=stage)
                        replied += 1
                    except (LoopHalt, EgressBlocked):
                        halted += 1
                if r.env.stage in TERMINAL_STAGES:
                    self.wd.close(r.env.conversation_id, f"peer_{r.env.stage}")
        return {"handled": handled, "replied": replied, "halted": halted}

    def close(self) -> None:
        self._save_identity()
