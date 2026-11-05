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
from .approvals import ApprovalError, ApprovalStore
from .audit import AuditLog, fingerprint, mask
from .crypto import (CryptoError, DecryptionError, KeyMismatchError,
                     KeyStore, SignatureError, b64d, b64e as _b64e,
                     fingerprint_of)
from .guard import (ALLOW, BLOCK, REDACT, EgressGuard, GuardResult, IngressGuard,
                    SCOPE_LAN, SCOPE_LOCAL, SCOPE_WAN, LEVEL_ORDER)
from .protocol import (ACT_NOTICE, ACT_RESULT, ACT_TASK, Budget, Envelope,
                       STAGE_DONE, TERMINAL_STAGES, make_task, new_id)
from .trust import (MATCH, MISMATCH, NEW, POLICY_TOFU, TrustStore, UNKNOWN)
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


class ApprovalRequired(EgressBlocked):
    """内容被拦下，但**已经挂起等人决定**，不是死路。

    继承 EgressBlocked 是有意的：它确实是"出站被闸门拦下"的一种，
    只是多了后续可能（人批准后能原样重发）。这样既有的
    ``except EgressBlocked`` 代码不用改就能继续工作，不会因为升级
    而突然漏掉一类本该拦住的东西。

    但三种区别必须说清楚：

    - 和 ``EgressBlocked`` 的区别：那条消息已经丢了（没存），这条还在队列里。
      所以 CLI 不能报"发送失败"，要报"等你决定"。
    - 和"已发送"的区别：它没有发出，对方什么都收不到。任何把它当成
      "发了"的处理都会造成"我说发了、你说没收到"。
    - 和"审批通过"的区别：``hold`` 只是排队，不是批准。别把排队当默许。
    """

    def __init__(self, pending: Dict[str, Any],
                 result: Optional[GuardResult] = None) -> None:
        pid = pending.get("id", "")
        # 不走 EgressBlocked.__init__：那句话是"未通过闸门"，而这里
        # 准确的说法是"拦下了，但等你决定"。措辞差别会改变人的下一步动作。
        LinkError.__init__(
            self, "approval_required",
            f"内容含敏感信息，已挂起等你决定（{pid}）。"
            f"看到内容：a2alink approvals show {pid}；"
            f"批准发送：a2alink approvals approve {pid} --reason \"...\" --yes；"
            f"拒绝：a2alink approvals deny {pid} --reason \"...\"")
        self.pending = pending
        self.result = result
        self.pending_id = pid


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
    # 发送前的明文 payload。env.payload 在加密后只剩占位符，
    # 想回看的调用方应该读这里（只在本进程内存里，不落盘）。
    plaintext: Optional[Dict[str, Any]] = None
    encrypted: bool = False
    kex_source: str = "none"


@dataclass
class Received:
    env: Envelope
    seq: int = 0
    ingress: Optional[GuardResult] = None
    verdict: Optional[Verdict] = None
    text: str = ""          # 已围栏化的安全文本
    quarantine: bool = False
    # 密码学状态。调用方应当先看这三个字段，再看 text。
    authenticated: bool = False          # 签名是否验过
    decrypted: bool = False              # 是否是解密得到的
    trust: Optional[Dict[str, Any]] = None   # 公钥固定判定（new/match/mismatch/...）
    reject_reason: str = ""              # 非空表示这条被拒收，text 必为空

    def to_dict(self) -> Dict[str, Any]:
        return {"envelope": self.env.to_dict(), "text": self.text,
                "quarantine": self.quarantine,
                "authenticated": self.authenticated,
                "decrypted": self.decrypted,
                "trust": self.trust,
                "reject_reason": self.reject_reason,
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
                 allow_forward: bool = False,
                 audit_log: Optional[AuditLog] = None,
                 audit_preview: int = 0,
                 audit_enabled: bool = True,
                 encrypt: str = "auto",
                 trust_policy: str = POLICY_TOFU,
                 require_signature: bool = True,
                 hold_on_block: bool = True,
                 approvals: Optional[ApprovalStore] = None) -> None:
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

        # 被拦下的内容默认**挂起等人决定**，而不是直接丢弃。
        # 直接丢会把使用者逼向一条更差的路：改成能过闸门的样子再发，
        # 于是审计链上留下一条干净的 allow，而真正的机密出去了。
        # 挂起件放在 ~/.a2alink/approvals 而不是本 agent 的 home：
        # 那是"本机所有人待处理的事"，分散到每个会话里就没人看了。
        self.hold_on_block = bool(hold_on_block)
        self.approvals = approvals or ApprovalStore()

        self.invite_code = invite_code
        self._cursor = 0
        self.agent_id = ""
        self.token = ""

        # ---------- 密码学身份 ----------
        # 密钥必须在注册**之前**加载：注册请求要把公钥一起交上去。
        # 私钥永远只在本机 <home>/keys/ 里，没有任何一条代码路径会把它发出去。
        if encrypt not in ("auto", "always", "never"):
            raise LinkError("bad_config", "encrypt 只能是 auto / always / never")
        self.encrypt = encrypt
        self.require_signature = bool(require_signature)
        self.keys = KeyStore(os.path.join(self.home, "keys")).load_or_create()
        self.trust = TrustStore(os.path.join(self.home, "trust"), policy=trust_policy)
        self._pub_cache: Dict[str, Dict[str, str]] = {}

        self._load_or_register(auto_register)

        # 审计链放在 <home>/logs 下，与身份文件同级。
        # 身份先加载，审计里的 actor 才有真名可写——否则日志里全是 "agent:?",
        # 出事时第一句话就会变成"这条不知道是谁"。
        self.audit = audit_log or AuditLog(
            os.path.join(self.home, "logs"), f"agent:{self.agent_id}",
            preview_chars=audit_preview, enabled=audit_enabled)
        self.audit.write("agent.boot", "note", "agent.boot",
                         detail={"agent": self.agent_id, "registry": self.registry,
                                 "scope": peer_scope,
                                 "preview_chars": audit_preview})

    def _audit(self, event: str, decision: str, reason: str,
               trace: Optional[str] = None, detail: Optional[Dict[str, Any]] = None,
               evidence: Optional[Dict[str, Any]] = None,
               preview: Optional[str] = None) -> None:
        """写审计。审计未启用时静默跳过（enabled=False 是显式的降级选择）。"""
        self.audit.write(event, decision, reason, trace=trace, detail=detail,
                         evidence=evidence, preview=preview)

    def _hold_blocked(self, egress: GuardResult, *, peer: str, scope: str,
                      act: str, stage: str, payload: Dict[str, Any],
                      trace: str, conversation_id: Optional[str],
                      in_reply_to: Optional[str], ttl_seconds: int,
                      ttl_hops: int) -> ApprovalRequired:
        """把被拦下的消息挂进审批队列，返回待 raise 的异常。

        返回异常而不是直接 raise，是为了让调用点只有一处 ``raise``，
        读代码时不会漏掉"这里其实还有一条出路"。
        """
        findings: List[Dict[str, Any]] = []
        for f in (egress.findings or []):
            try:
                findings.append(f.to_dict())
            except AttributeError:
                findings.append({"rule": str(getattr(f, "rule", "unknown"))})
        try:
            pending = self.approvals.hold(
                requester=self.agent_id, session=self.name, peer=peer,
                scope=scope, act=act, stage=stage, payload=payload,
                findings=findings, level=egress.level, trace=trace,
                replay={"ttl_seconds": ttl_seconds, "ttl_hops": ttl_hops,
                        "conversation_id": conversation_id,
                        "in_reply_to": in_reply_to})
        except (ApprovalError, OSError) as e:
            # 挂不住（磁盘满、权限、密钥坏了）就只能回到"拦死"。
            # 但必须把原因写进审计：否则使用者只看到"发送失败"，
            # 会以为是网络问题而反复重试。
            self._audit("gate.egress", "deny", "egress.hold_failed", trace,
                        detail={"peer": peer, "err": str(e)[:160]},
                        evidence=fingerprint(payload))
            return ApprovalRequired(
                {"id": "", "status": "pending", "peer": peer,
                 "rules": sorted({f["rule"] for f in findings})},
                egress)
        self._audit("gate.egress", "note", "gate.hold", trace,
                    detail={"peer": peer, "pending": pending["id"],
                            "rules": pending["rules"], "level": egress.level,
                            "expires_at": pending.get("expires_at")},
                    evidence=fingerprint(payload))
        return ApprovalRequired(pending, egress)

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
                    self._ensure_published()
                    return
            except (OSError, ValueError, KeyError):
                pass
        if not auto_register:
            raise LinkError("no_identity", "本地没有身份文件，且未开启自动注册")
        pub = self.keys.public_bundle()
        out = self._api("POST", "/v1/agents/register", {
            "name": self.name, "capabilities": self.capabilities,
            "description": self.description, "invite_code": self.invite_code,
            "sign_pub": pub["sign_pub"], "kex_pub": pub["kex_pub"],
        }, auth=False)
        self.agent_id, self.token = out["agent_id"], out["token"]
        self.name = out.get("name", self.name)
        self._save_identity()
        if not os.environ.get("A2ALINK_QUIET"):
            print(f"[a2alink] 已注册身份 {self.name} ({self.agent_id})")
            print(f"[a2alink] 签名公钥指纹: {pub['fingerprint']}")
            print(f"[a2alink] 私钥文件: {self.keys.root}（权限 600，请勿提交仓库）")

    def _ensure_published(self) -> None:
        """本地已有身份但要确认公钥已登记到注册中心。

        用本地公钥和注册中心记录做比对：不一致说明要么本地换过钥匙
        却没上传，要么服务器上的记录被人动过。两种情况都要说出来，
        而不是静默地把公钥重传一遍——重传会把"被人改过"这件事擦掉。
        """
        try:
            me = self._api("GET", f"/v1/agents/{self.agent_id}")
        except LinkError:
            return                      # 服务端不可达时不在构造阶段报错
        remote = me.get("sign_pub") or ""
        local = self.keys.signing.public_b64
        if not remote:
            self._publish_keys(reason="首次上传（本地身份早于公钥机制）")
        elif remote != local:
            if not os.environ.get("A2ALINK_QUIET"):
                print(f"[a2alink] ⚠️ 注册中心记录的签名公钥与本地不一致。\n"
                      f"          本地: {fingerprint_of(self.keys.signing.public_bytes)}\n"
                      f"          远端记录已变更。若这是你自己轮换过密钥，"
                      f"请执行 a2alink keys publish；否则可能有人在动你的登记信息。")

    def _publish_keys(self, reason: str = "") -> Dict[str, Any]:
        """把本机公钥登记到注册中心。只发公钥，不发私钥。"""
        pub = self.keys.public_bundle()
        return self._api("PUT", "/v1/agents/me/keys", {
            "sign_pub": pub["sign_pub"], "kex_pub": pub["kex_pub"],
            "reason": reason})

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

    # ------------------------------------------------------------------
    # 公钥
    # ------------------------------------------------------------------
    def peer_public(self, peer: str, refresh: bool = False) -> Dict[str, str]:
        """取对端公钥。**本地固定优先于注册中心**。

        这个优先级不能反：注册中心是可以被攻陷、被运营方改、被中间人劫持的，
        而本地 pin 只有在"你亲手改过"之后才会变。发加密消息时拿错公钥的
        后果是把内容加密给了攻击者，而且全程没有任何报错——这是最危险的一类失败。
        """
        if not refresh:
            kex = self.trust.known_kex_pub(peer)
            if kex:
                return {"kex_pub": _b64e(kex), "source": "pinned"}
            if peer in self._pub_cache:
                return self._pub_cache[peer]
        try:
            a = self._api("GET", f"/v1/agents/{peer}")
        except LinkError:
            return {}
        d = {"sign_pub": a.get("sign_pub", ""), "kex_pub": a.get("kex_pub", ""),
             "key_fp": a.get("key_fp", ""), "source": "registry"}
        self._pub_cache[peer] = d
        return d

    def _seal_and_sign(self, env: Envelope, peer: str, is_group: bool,
                       trace: str) -> Tuple[bool, str]:
        """给信封加密 + 签名。返回 (是否加密, 密钥来源)。

        顺序：先加密再签名。反过来的话签名不覆盖密文，攻击者可以
        把密文换成自己的而签名仍然有效。
        """
        encrypted, src = False, "none"
        if not is_group and self.encrypt != "never":
            kex = self.trust.known_kex_pub(peer)
            src = "pinned"
            if kex is None:
                info = self.peer_public(peer)
                kb = info.get("kex_pub")
                if kb:
                    if self.trust.policy == "strict":
                        raise LinkError(
                            "unpinned_peer_key",
                            f"strict 信任策略下不接受注册中心下发的公钥（{peer}）。"
                            "请先用 a2alink keys pin 导入并核对指纹。")
                    try:
                        kex = b64d(kb)
                    except CryptoError:
                        kex = None
                    src = "registry"
            if kex:
                env.seal_payload(kex)
                encrypted = True
            elif self.encrypt == "always":
                raise LinkError(
                    "no_peer_key",
                    f"encrypt=always 但拿不到 {peer} 的交换公钥，拒绝发送明文。"
                    "可以等对方上线后重试，或把 encrypt 改成 auto。")
        env.sign(self.keys)
        self._audit("crypto.seal", "allow" if encrypted else "note",
                    "crypto.sealed" if encrypted else (
                        "crypto.group_plaintext" if is_group else "crypto.plaintext"),
                    trace, detail={"peer": peer, "kex_source": src,
                                   "encrypted": encrypted, "is_group": is_group,
                                   "my_fp": self.keys.signing.fingerprint})
        return encrypted, src

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
             force: bool = False, force_reason: str = "",
             in_reply_to: Optional[str] = None,
             forwarded_from: Optional[str] = None) -> Sent:
        """发一条信封。内部顺序：DLP → 扩散保险丝 → 看门狗 → 网络。任何一步不过就不发。

        每一步的裁决都会写进审计链，包括"通过了"。
        因为事后要证明的常常不是"我拦了"，而是"我查过"。

        force=True 必须同时给 force_reason（≥8 字），否则直接拒绝。
        这个限制不是为了难用人，是因为一个不需要填理由的"强行放行"按钮，
        在真实团队里三个月内一定会变成默认操作。理由会进审计链，责任在人。
        """
        trace = new_id("trace-")     # 在闸门之前生成：被拦的消息也要有可追溯的 ID
        peer = to if to.startswith(("agt-", "grp-")) else self.resolve(to)
        is_group = peer.startswith("grp-")
        scope = SCOPE_LAN if is_group else self._scope_for(peer)
        self.egress.scope = scope
        fp = fingerprint(payload)
        preview = str(payload.get("instruction", "") or "")

        # ---------- 0) 强行放行必须给理由，否则不给发 ----------
        if force and len(str(force_reason).strip()) < 8:
            self._audit("gate.override", "drop", "egress.override", trace,
                        detail={"peer": peer, "error": "force_without_reason",
                                "given": str(force_reason)[:40]}, evidence=fp)
            raise LinkError("force_requires_reason",
                            "force=True 必须同时提供 force_reason（至少 8 个字），"
                            "说明为什么这段内容经人确认可以出域。理由会写入审计链。")

        # ---------- 1) 出站 DLP ----------
        egress, clean_payload = self.egress.check_payload(payload)
        rules = sorted({f.rule for f in egress.findings})
        base = {"peer": peer, "scope": scope, "act": act, "level": egress.level,
                "rules": rules, "findings": len(egress.findings)}
        if egress.action == BLOCK:
            if not force:
                # 挂起时**不写** egress.deny：这条内容并没有被丢弃，它还在
                # 队列里等人决定。两样都写会让报告里"拦截"和"挂起"重复计数，
                # 而这两个数回答的是不同问题——
                # "多少内容被彻底挡住" vs "多少在等人做决定"。
                if self.hold_on_block:
                    raise self._hold_blocked(
                        egress, peer=peer, scope=scope, act=act, stage=stage,
                        payload=payload, trace=trace,
                        conversation_id=conversation_id, in_reply_to=in_reply_to,
                        ttl_seconds=ttl_seconds, ttl_hops=ttl_hops)
                self._audit("gate.egress", "deny", "egress.deny", trace,
                            detail=base, evidence=fp, preview=preview)
                raise EgressBlocked(egress)
            self._audit("gate.egress", "note", "egress.override", trace,
                        detail={**base, "force_reason": force_reason,
                                "human_confirmed": True},
                        evidence=fp, preview=preview)
        elif egress.action == REDACT:
            self._audit("gate.egress", "redact", "egress.redact", trace,
                        detail=base, evidence=fp, preview=preview)
        else:
            self._audit("gate.egress", "allow", "egress.allow", trace,
                        detail=base, evidence=fp, preview=preview)

        # ---------- 2) 转发闸门与扩散保险丝 ----------
        if forwarded_from:
            try:
                self.propagation.check_forward(forwarded_from)
            except (PropagationBlocked, ProvenanceError) as e:
                self._audit("gate.propagation", "deny", "propagation.deny_forward", trace,
                            detail={"peer": peer, "from": forwarded_from,
                                    "err": str(e)[:80]}, evidence=fp)
                raise
            clean_payload = dict(clean_payload)
            clean_payload["_provenance"] = {"forwarded_from": forwarded_from,
                                            "stated_by": self.agent_id,
                                            "note": "本条为转发，非说话人原创"}
        conv = conversation_id or new_id("conv-")
        try:
            self.propagation.check(
                json.dumps(clean_payload, ensure_ascii=False, sort_keys=True), conv, peer)
            self._audit("gate.propagation", "allow", "propagation.allow", trace,
                        detail={"conv": conv, "peer": peer}, evidence=fp)
        except PropagationBlocked as e:
            if not force:
                self._audit("gate.propagation", "deny", "propagation.deny_fanout", trace,
                            detail={"conv": conv, "peer": peer, "err": str(e)[:80]},
                            evidence=fp)
                raise
            self._audit("gate.propagation", "note", "propagation.override", trace,
                        detail={"conv": conv, "peer": peer, "force_reason": force_reason,
                                "human_confirmed": True}, evidence=fp)

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
            trace_id=trace,
        )

        # ---------- 3) 循环治理 ----------
        verdict = self.wd.check_outbound(env)
        wdet = {"conv": conv, "peer": peer, "action": verdict.action,
                "reasons": verdict.reasons[:4], "stats": verdict.stats}
        if verdict.action == STOP:
            if not force:
                self._audit("gate.watchdog", "deny", "watchdog.deny", trace,
                            detail=wdet, evidence=fp, preview=preview)
                raise LoopHalt(verdict)
            self._audit("gate.watchdog", "note", "watchdog.override", trace,
                        detail={**wdet, "force_reason": force_reason,
                                "human_confirmed": True}, evidence=fp, preview=preview)
        elif verdict.action == DEGRADE:
            self._audit("gate.watchdog", "note", "watchdog.degrade", trace,
                        detail=wdet, evidence=fp)
        else:
            self._audit("gate.watchdog", "allow", "watchdog.allow", trace,
                        detail=wdet, evidence=fp)

        # ---------- 4) 加密 + 签名 ----------
        # 放在看门狗**之后**：加密后 payload 只剩占位符，看门狗的内容指纹
        # 就失效了（"两个 Agent 互相发乱码"也会被当成不同内容放行）。
        plain = dict(clean_payload)
        encrypted, kex_src = self._seal_and_sign(env, peer, is_group, trace)

        # ---------- 5) 真正出网 ----------
        try:
            out = self._api("POST", "/v1/messages", {"envelope": env.to_dict()})
        except LinkError as e:
            self._audit("wire.send", "deny", "wire.send_failed", trace,
                        detail={"peer": peer, "code": e.code,
                                "status": e.status, "msg": e.message[:80]},
                        evidence=fp)
            raise
        dup = bool(out.get("duplicate"))
        self._audit("wire.send", "note" if dup else "allow",
                    "wire.duplicate" if dup else "wire.sent", trace,
                    detail={"peer": peer, "to_type": env.to_type, "msg_id": env.id,
                            "delivered_to": out.get("delivered_to", 0),
                            "server_seq": out.get("seq", 0),
                            "hops": env.ttl_hops}, evidence=fp)
        return Sent(env=env, delivered_to=out.get("delivered_to", 0),
                    duplicate=dup, egress=egress,
                    verdict=verdict, seq=out.get("seq", 0),
                    plaintext=plain, encrypted=encrypted, kex_source=kex_src)

    def send_text(self, to: str, text: str, act: str = ACT_TASK,
                  stage: str = "open", **kw: Any) -> Sent:
        return self.send(to, {"instruction": text}, act=act, stage=stage, **kw)

    def reply(self, received: "Received", payload: Dict[str, Any],
              stage: str = STAGE_DONE, act: str = ACT_RESULT,
              force: bool = False, force_reason: str = "") -> Sent:
        """标准回信：继承会话、递减 TTL、把预算用量还回去。

        回信复用原信封的 trace_id —— 一次对话的所有往返共用一条 trace，
        排查时用 `a2alink trace <id>` 就能拉出完整时间线。
        """
        env = received.env
        child = env.reply(self.agent_id, payload, act=act, stage=stage)
        trace = child.trace_id or env.trace_id or new_id("trace-")
        fp = fingerprint(payload)
        preview = str(payload.get("instruction", "") or "")

        if force and len(str(force_reason).strip()) < 8:
            self._audit("gate.override", "drop", "egress.override", trace,
                        detail={"peer": child.to_id, "error": "force_without_reason"},
                        evidence=fp)
            raise LinkError("force_requires_reason",
                            "force=True 必须同时提供 force_reason（至少 8 个字）")

        egress, clean = self.egress.check_payload(payload)
        rules = sorted({f.rule for f in egress.findings})
        base = {"peer": child.to_id, "stage": stage, "rules": rules,
                "level": egress.level, "conv": child.conversation_id}
        if egress.action == BLOCK:
            if not force:
                self._audit("gate.egress", "deny", "egress.deny", trace,
                            detail=base, evidence=fp, preview=preview)
                raise EgressBlocked(egress)
            self._audit("gate.egress", "note", "egress.override", trace,
                        detail={**base, "force_reason": force_reason,
                                "human_confirmed": True}, evidence=fp, preview=preview)
        elif egress.action == REDACT:
            self._audit("gate.egress", "redact", "egress.redact", trace,
                        detail=base, evidence=fp, preview=preview)
        else:
            self._audit("gate.egress", "allow", "egress.allow", trace,
                        detail=base, evidence=fp, preview=preview)
        child.payload = clean

        # 回信也要过扩散保险丝：否则"先试探一次，然后靠自动回复扩散"就成了绕过口。
        try:
            self.propagation.check(
                json.dumps(clean, ensure_ascii=False, sort_keys=True),
                child.conversation_id, child.to_id)
            self._audit("gate.propagation", "allow", "propagation.allow", trace,
                        detail={"conv": child.conversation_id, "peer": child.to_id},
                        evidence=fp)
        except PropagationBlocked as e:
            if not force:
                self._audit("gate.propagation", "deny", "propagation.deny_fanout", trace,
                            detail={"conv": child.conversation_id, "peer": child.to_id,
                                    "err": str(e)[:80]}, evidence=fp)
                raise
            self._audit("gate.propagation", "note", "propagation.override", trace,
                        detail={"conv": child.conversation_id, "force_reason": force_reason,
                                "human_confirmed": True}, evidence=fp)

        verdict = self.wd.check_outbound(child)
        wdet = {"conv": child.conversation_id, "action": verdict.action,
                "reasons": verdict.reasons[:4]}
        if verdict.action == STOP:
            if not force:
                self._audit("gate.watchdog", "deny", "watchdog.deny", trace,
                            detail=wdet, evidence=fp, preview=preview)
                raise LoopHalt(verdict)
            self._audit("gate.watchdog", "note", "watchdog.override", trace,
                        detail={**wdet, "force_reason": force_reason,
                                "human_confirmed": True}, evidence=fp)
        else:
            self._audit("gate.watchdog", "allow", "watchdog.allow", trace,
                        detail=wdet, evidence=fp)

        # 回信同样要加密 + 签名。跳过这一步等于给攻击者留了个后门：
        # "首发消息很规矩，但所有回复都是明文的"。
        plain = dict(clean)
        encrypted, kex_src = self._seal_and_sign(child, child.to_id, False, trace)

        try:
            out = self._api("POST", "/v1/messages", {"envelope": child.to_dict()})
        except LinkError as e:
            self._audit("wire.send", "deny", "wire.send_failed", trace,
                        detail={"peer": child.to_id, "code": e.code,
                                "msg": e.message[:80]}, evidence=fp)
            raise
        self._audit("wire.send", "allow", "wire.sent", trace,
                    detail={"peer": child.to_id, "msg_id": child.id,
                            "delivered_to": out.get("delivered_to", 0),
                            "hops": child.ttl_hops}, evidence=fp)
        return Sent(env=child, delivered_to=out.get("delivered_to", 0),
                    egress=egress, verdict=verdict, seq=out.get("seq", 0),
                    plaintext=plain, encrypted=encrypted, kex_source=kex_src)

    # ------------------------------------------------------------------
    # 数据面：接收（内置入站闸门 + 看门狗）
    # ------------------------------------------------------------------
    def recv(self, wait: float = 0.0, limit: int = 20, auto_ack: bool = True) -> List[Received]:
        raw = self._api("GET", "/v1/inbox",
                        qs=f"cursor={self._cursor}&limit={limit}&wait={wait}")
        out: List[Received] = []
        for d in raw.get("items", []):
            seq = int(d.pop("_seq", 0))
            trace_hint = str(d.get("trace_id") or "")
            try:
                env = Envelope.from_dict(d)
            except Exception as e:
                # 畸形信封直接丢弃，不进入上下文。
                # 但**必须留痕**：静默 continue 会让"一条消息凭空消失"
                # 变成永远查不清的悬案，而它恰恰可能是攻击的第一发。
                self._audit("wire.recv", "drop", "wire.dropped_malformed", trace_hint,
                            detail={"seq": seq, "err": f"{type(e).__name__}",
                                    "from": str(d.get("from_agent", ""))[:40]})
                self._cursor = max(self._cursor, seq)
                continue

            # ---------- 1) 验签：不过就不许进上下文 ----------
            # 顺序不能调：先解密再验签，等于让未认证的密文先消耗一次
            # 椭圆曲线运算（可被用来做 CPU 耗尽），而且解密结果一旦
            # 因为后续验签失败被丢掉，它其实已经进过内存了。
            if not env.signature and not self.require_signature:
                # 显式关闭签名的降级路径。会持续在审计里刷 note，
                # 目的是让"我们关掉了签名校验"这件事无法被忘掉。
                authenticated = False
                info = {"sign_pub": b"", "kex_pub": b""}
                td = {"decision": "skipped", "fp": "",
                      "detail": "require_signature=False，未签名消息被放行"}
                self._audit("crypto.verify", "note", "crypto.signature_skipped",
                            trace_hint,
                            detail={"seq": seq, "from": env.from_agent})
            else:
                try:
                    info = env.verify()
                    authenticated = True
                except (SignatureError, KeyMismatchError, CryptoError) as e:
                    kind = "signature" if isinstance(e, SignatureError) else "key"
                    self._audit("wire.recv", "deny", "wire.bad_signature", trace_hint,
                                detail={"seq": seq, "from": env.from_agent[:64],
                                        "kind": type(e).__name__,
                                        "err": str(e)[:120]})
                    out.append(Received(env=env, seq=seq, text="", quarantine=True,
                                        authenticated=False,
                                        reject_reason=f"签名无效：{e}"))
                    self._cursor = max(self._cursor, seq)
                    continue

                # ---------- 2) 公钥固定：这把钥匙真的属于这个 agent 吗 ----------
                td = self.trust.check(env.from_agent, info["sign_pub"],
                                      info["kex_pub"] or None)
                decision = td["decision"]
                if decision in (MISMATCH, UNKNOWN):
                    self.trust.record_mismatch(env.from_agent, td["fp"], "rejected")
                    self._audit("crypto.trust", "deny", "crypto.key_changed", trace_hint,
                                detail={"seq": seq, "from": env.from_agent,
                                        "decision": decision, "fp": td["fp"],
                                        "old_fp": td.get("old_fp", "")})
                    out.append(Received(env=env, seq=seq, text="", quarantine=True,
                                        authenticated=True, trust=td,
                                        reject_reason=f"公钥不可信（{decision}）：{td['detail']}"))
                    self._cursor = max(self._cursor, seq)
                    continue
                if decision == NEW:
                    # 首次见到这个对端。放行，但要让运维知道"这个信任是自动建立的"。
                    self._audit("crypto.trust", "note", "crypto.pin_new", trace_hint,
                                detail={"seq": seq, "from": env.from_agent,
                                        "fp": td["fp"], "kex_fp": td.get("kex_fp", ""),
                                        "note": "TOFU 首次记录，指纹未带外核对"})

            # ---------- 3) 解密 ----------
            decrypted = False
            if env.is_encrypted():
                try:
                    env.payload = env.open_payload(self.keys.kex)
                    decrypted = True
                    self._audit("crypto.open", "allow", "crypto.opened", trace_hint,
                                detail={"seq": seq, "from": env.from_agent})
                except (DecryptionError, CryptoError) as e:
                    self._audit("crypto.open", "deny", "crypto.decrypt_failed",
                                trace_hint,
                                detail={"seq": seq, "from": env.from_agent,
                                        "err": type(e).__name__})
                    out.append(Received(env=env, seq=seq, text="", quarantine=True,
                                        authenticated=True, trust=td,
                                        reject_reason=f"解密失败：{e}"))
                    self._cursor = max(self._cursor, seq)
                    continue
            elif self.encrypt in ("auto", "always"):
                # 对端发了明文。这不是错误（对方可能没登记公钥），
                # 但必须留痕——"这段对话里哪几条是明文"是事后要回答的问题。
                self._audit("crypto.open", "note", "crypto.plaintext_inbound",
                            trace_hint,
                            detail={"seq": seq, "from": env.from_agent})

            verdict = self.wd.check_inbound(env)
            if verdict.action == STOP:
                self._audit("gate.watchdog", "deny", "watchdog.deny", env.trace_id,
                            detail={"dir": "in", "conv": env.conversation_id,
                                    "from": env.from_agent,
                                    "reasons": verdict.reasons[:4]})
                out.append(Received(env=env, seq=seq, verdict=verdict,
                                    text="", quarantine=False,
                                    authenticated=authenticated,
                                    decrypted=decrypted, trust=td))
                self._cursor = max(self._cursor, seq)
                continue

            # 群消息加一个来源标签；单聊不需要
            source = f"agent:{env.from_agent}"
            if env.to_type == "group":
                source += f"@group:{env.to_id}"
            ing, fenced = self.ingress.check_and_fence(env.payload_text(), source)
            if ing.ok:
                self._audit("gate.ingress", "allow", "ingress.allow", env.trace_id,
                            detail={"from": env.from_agent, "to": env.to_id,
                                    "act": env.act, "stage": env.stage, "seq": seq},
                            evidence=fingerprint(env.payload_text()))
            else:
                self._audit("gate.ingress", "deny", "ingress.quarantine", env.trace_id,
                            detail={"from": env.from_agent, "to": env.to_id,
                                    "seq": seq,
                                    "rules": sorted({f.rule for f in ing.findings})[:6]},
                            evidence=fingerprint(env.payload_text()),
                            preview=env.payload_text())
            out.append(Received(env=env, seq=seq, ingress=ing, verdict=verdict,
                                text=fenced if ing.ok else "",
                                quarantine=not ing.ok,
                                authenticated=authenticated,
                                decrypted=decrypted, trust=td))
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
    # 处理确认：已读 != 做完
    # ------------------------------------------------------------------
    def done(self, message_ids: Any) -> Dict[str, Any]:
        """声明"这些我做完了"。传入单个 ID 或 ID 列表。

        别把它当成 ack 的别名。ack 是传输层的事（位点往前挪），
        done 是业务层的事（这件事有结果了）。Agent 读完崩掉时，
        两者必须留下不同的痕迹——否则排查时看到的永远是"一切正常"。
        """
        ids = [message_ids] if isinstance(message_ids, str) else list(message_ids or [])
        if not ids:
            return {"done": 0}
        return self._api("POST", "/v1/inbox/done", {"message_ids": ids})

    def fail(self, message_id: str, reason: str = "",
             requeue: bool = True) -> Dict[str, Any]:
        """声明"这条我处理不了"。requeue=True 时服务端会重新投一次。"""
        return self._api("POST", "/v1/inbox/fail",
                         {"message_id": message_id, "reason": reason,
                          "requeue": bool(requeue)})

    def inflight(self, limit: int = 50) -> Dict[str, Any]:
        """已读但没标完成的消息——"可能掉在地上的任务"清单。"""
        return self._api("GET", "/v1/inbox/inflight", qs=f"limit={int(limit)}")

    def dlq(self, limit: int = 50) -> Dict[str, Any]:
        return self._api("GET", "/v1/dlq", qs=f"limit={int(limit)}")

    def dlq_requeue(self, message_id: str) -> Dict[str, Any]:
        return self._api("POST", "/v1/dlq/requeue", {"message_id": message_id})

    def dlq_purge(self, message_id: str = "") -> Dict[str, Any]:
        return self._api("POST", "/v1/dlq/purge", {"message_id": message_id})

    # ------------------------------------------------------------------
    # 遗嘱消息
    # ------------------------------------------------------------------
    def set_will(self, to: str, text: str, ttl_seconds: int = 600,
                 force: bool = False, force_reason: str = "") -> Dict[str, Any]:
        """立遗嘱：预先签好一条消息交给中继保管，掉线后由它代发。

        三个必须在这里做、不能交给服务端的决定：
        1. **内容先过 DLP**。遗嘱也是一条出站消息，不过闸就等于给自己
           留了一条"临终泄密"通道——而这恰恰是最容易被忽略的一条。
        2. **加密在本地做**。中继存的是密文，它自己也读不到遗嘱写的什么。
        3. **签名在本地做**。中继没有私钥，它只能转交一封已经签好的信。
        """
        target = self.resolve(to)
        trace = new_id("trace-")
        egress, clean = self.egress.check_payload({"instruction": text})
        rules = sorted({f.rule for f in egress.findings})
        fp = fingerprint({"instruction": text})
        if egress.action == BLOCK:
            if not force:
                self._audit("gate.egress", "deny", "egress.deny", trace,
                            detail={"peer": target, "rules": rules, "will": True},
                            evidence=fp)
                raise EgressBlocked(egress)
            self._audit("gate.egress", "note", "egress.override", trace,
                        detail={"peer": target, "rules": rules, "will": True,
                                "force_reason": force_reason, "human_confirmed": True},
                        evidence=fp)

        ttl = int(ttl_seconds or 0)
        if ttl and not (30 <= ttl <= 86400):
            # 不静默钳制。把 5 秒改成 30 秒，用户会以为 5 秒后就有人知道，
            # 实际要等 30 秒——这种"帮你修正参数"比直接报错危险得多。
            raise LinkError("bad_ttl", f"遗嘱 TTL 必须在 30~86400 秒之间（收到 {ttl}）")
        eff = ttl or 600
        now = time.time()
        env = Envelope(
            id=new_id(), from_agent=self.agent_id, to_type="agent", to_id=target,
            act=ACT_NOTICE, stage=STAGE_DONE, payload=clean,
            conversation_id=new_id("conv-"), created_at=now,
            # 遗嘱可能几小时后才发出去，所以有效期要留够；但也必须有尽头——
            # 一封永不过期的信躺在别人队列里，就是一条永远不会有人收的僵尸任务。
            expires_at=now + max(3600.0, eff * 6.0),
            ttl_hops=1, trace_id=trace,
        )
        self._seal_and_sign(env, target, False, trace)
        out = self._api("PUT", "/v1/agents/me/will",
                        {"envelope": env.to_dict(), "ttl_seconds": ttl})
        self._audit("gate.egress", "allow", "egress.allow", trace,
                    detail={"peer": target, "rules": rules, "level": egress.level,
                            "will": True}, evidence=fp)
        out["message_id"] = env.id
        return out

    def clear_will(self) -> Dict[str, Any]:
        return self._api("DELETE", "/v1/agents/me/will")

    def will_info(self) -> Dict[str, Any]:
        return self._api("GET", "/v1/agents/me/will")

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
        self._audit("agent.exit", "note", "agent.exit",
                    detail={"cursor": self._cursor, "seq": self.audit._seq})
        self._save_identity()
        self.audit.close()
