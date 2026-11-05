"""A2A Link —— 面向 AI Agent 的对等通信协议（零第三方依赖）。

=========================== 三条硬规矩 ===========================
1) 信封（envelope）与载荷（payload）分离
   信封是**路由器能看懂的最小集合**，载荷只有通信两端看得懂。
   好处：中继网关可以盲转发，既不触达业务内容，也顺带把"通信服务资质"
   的问题降级成"传输管道"的问题；带宽也只有正常 IM 的 1/5。

2) 信封自带 TTL / hop / budget 三重递减量
   这是分布式环境下唯一真正能掐死"两个 Agent 互相刷屏到天亮"的机制。
   看门狗（watchdog.py）不靠猜，只靠这三个数。

3) 幂等键 + 至少一次投递
   不承诺 exactly-once（分布式下这是谎话），但保证重复投递无副作用。

⚠️ 安全前提：**任何来自外部的 Agent 消息都是不可信输入**，等价于"公网上
   任意一段文本直接进你的 LLM 上下文"。发出前必须过 guard.EgressGuard，
   收进后必须过 guard.IngressGuard。默认拒绝，而不是默认放行。
"""

from __future__ import annotations

import hashlib
import hmac
import json
import math
import re
import time
import uuid
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional

PROTOCOL_VERSION = "1"

# 消息动作类型（语义层）。刻意不用 IM 的 "message/chat" 一元模型：
# 一元的 chat 语义无法表达"任务—结果—终止"，这是 Agent 无限对话的根因。
ACT_TASK = "task"          # 派活：我需要你做一件事
ACT_RESULT = "result"      # 交活：这是结果
ACT_EVENT = "event"        # 事件通知：告警、状态变更（不需要回复）
ACT_CHAT = "chat"          # 闲聊/协商，建议极少用
ACT_NOTICE = "notice"      # 协议级通知：拒收、熔断、TTL 耗尽
ACTS = (ACT_TASK, ACT_RESULT, ACT_EVENT, ACT_CHAT, ACT_NOTICE)

# 会话阶段。**必须由 Agent 显式发出终止信号**，不要指望看门狗来收尾。
STAGE_OPEN = "open"
STAGE_DONE = "done"             # 我做完了，别再回我
STAGE_HANDOFF = "handoff"       # 交棒给第三方，我不再接这条链
STAGE_NEED_HUMAN = "need_human" # 需要人介入
STAGE_BLOCKED = "blocked"       # 被安全策略拦住
STAGES = (STAGE_OPEN, STAGE_DONE, STAGE_HANDOFF, STAGE_NEED_HUMAN, STAGE_BLOCKED)
TERMINAL_STAGES = (STAGE_DONE, STAGE_HANDOFF, STAGE_NEED_HUMAN, STAGE_BLOCKED)

MAX_HOPS_HARD_LIMIT = 16
MAX_ENVELOPE_BYTES = 64 * 1024
# 回复链最多记这么多条。抄的是 SMTP 的 References 头，但加了一道收口：
# 链是**无界增长**的（A 问 B、B 问 C、C 问 D……），照原样累积下去，
# 一百轮转手就能把信封撑到超过 MAX_ENVELOPE_BYTES，那时候报的错会是
# "信封超长"，没人想得到根因是"回复链太长"。
MAX_REFERENCES = 8

_CJK = re.compile(r"[\u3400-\u4dbf\u4e00-\u9fff\u3040-\u30ff\uac00-\ud7af]")


class ProtocolError(ValueError):
    """信封格式非法。上层应视为攻击面，按不可信输入处理。"""


def _reject_constant(name: str):
    """给 json.loads 的 parse_constant 用：遇到 NaN/Infinity 直接拒绝。"""
    raise ProtocolError(f"JSON 里不允许出现 {name}（非标准字面量）")


def new_id(prefix: str = "") -> str:
    u = uuid.uuid4().hex[:24]
    return f"{prefix}{u}" if prefix else u


def estimate_tokens(text: str) -> int:
    """粗估 token 数。中文按 1 字 1 token，拉丁文按 4 字符 1 token。

    故意保守（宁可高估）：看门狗的存在意义是止损，不是精确计费。
    """
    if not text:
        return 0
    cjk = len(_CJK.findall(text))
    rest = max(0, len(text) - cjk)
    return cjk + (rest + 3) // 4


# --------------------------------------------------------------------------
# 预算：跟着信封一起走，谁用谁扣，回程自动带回去
# --------------------------------------------------------------------------
@dataclass
class Budget:
    max_messages: int = 20       # 这条会话最多允许几条消息
    max_tokens: int = 20000      # 这条会话最多烧多少 token
    used_messages: int = 0
    used_tokens: int = 0

    def remaining_messages(self) -> int:
        return max(0, self.max_messages - self.used_messages)

    def remaining_tokens(self) -> int:
        return max(0, self.max_tokens - self.used_tokens)

    def exhausted(self) -> bool:
        return self.remaining_messages() == 0 or self.remaining_tokens() <= 0

    def to_dict(self) -> Dict[str, int]:
        return asdict(self)

    @staticmethod
    def from_dict(d: Any) -> "Budget":
        if not isinstance(d, dict):
            return Budget()
        def _i(k, default=0):
            v = d.get(k, default)
            if not isinstance(v, int) or isinstance(v, bool) or v < 0:
                raise ProtocolError(f"budget.{k} 必须是非负整数")
            return v
        b = Budget(_i("max_messages", 20), _i("max_tokens", 20000),
                   _i("used_messages"), _i("used_tokens"))
        if b.max_messages < 1 or b.max_tokens < 1:
            raise ProtocolError("budget.max_* 必须 >= 1")
        return b


@dataclass
class Envelope:
    """A2A 信封。字段只增不删（协议演进留余地），新增字段一律可选。"""

    id: str
    from_agent: str
    to_type: str                 # "agent" | "group"
    to_id: str
    act: str
    payload: Dict[str, Any]
    conversation_id: str
    created_at: float
    expires_at: float
    ttl_hops: int
    stage: str = STAGE_OPEN
    in_reply_to: Optional[str] = None
    # 整条回复链（SMTP References 的消息版）。in_reply_to 只说"我回的是谁"，
    # 转手两次之后就没人答得上来"最初问的是什么、中间谁改了措辞"。
    # ⚠️ 它参与签名，但**为空时不出现在 to_dict 里**——这样 0.4 之前的
    # 信封规范字节完全不变，历史消息照样能验签（见 canonical_bytes）。
    references: List[str] = field(default_factory=list)
    correlation_id: Optional[str] = None
    idempotency_key: Optional[str] = None
    budget: Budget = field(default_factory=Budget)
    capabilities: List[str] = field(default_factory=list)  # 本条消息请求的能力
    trace_id: Optional[str] = None
    signature: Optional[str] = None
    # 发送者公钥。⚠️ 它的作用**不是**"我拿出公钥所以你该信我"——那是自签
    # 自验的死循环。真正的信任来自接收方本地的公钥固定（pin，见 crypto.pin）。
    # 放在信封里只是省一次往返，并让"这一版用的哪把钥匙"可追溯。
    pub: Optional[Dict[str, str]] = None
    # 端到端加密块。存在即表示 payload 已被加密（payload 只剩占位）。
    enc: Optional[Dict[str, str]] = None
    v: str = PROTOCOL_VERSION

    # ---------------- 序列化 ----------------
    def to_dict(self) -> Dict[str, Any]:
        d = {
            "v": self.v,
            "id": self.id,
            "from": self.from_agent,
            "to": {"type": self.to_type, "id": self.to_id},
            "act": self.act,
            "stage": self.stage,
            "conversation_id": self.conversation_id,
            "in_reply_to": self.in_reply_to,
            "correlation_id": self.correlation_id,
            "idempotency_key": self.idempotency_key,
            "created_at": self.created_at,
            "expires_at": self.expires_at,
            "ttl_hops": self.ttl_hops,
            "budget": self.budget.to_dict(),
            "capabilities": list(self.capabilities),
            "trace_id": self.trace_id,
            "payload": self.payload,
            "pub": self.pub,
            "enc": self.enc,
            "signature": self.signature,
        }
        # 空链**不落字段**。这不是省字节，是兼容性：canonical_bytes 直接
        # 序列化 to_dict()，多一个 "references": [] 就会让所有 0.3 信封的
        # 签名校验失败——一次"加功能"变成"历史消息全部不认"。
        if self.references:
            d["references"] = list(self.references)
        return d

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False, separators=(",", ":"))

    def canonical_bytes(self) -> bytes:
        """签名用字节流：排除 signature 本身，字段顺序固定。

        覆盖范围包括 pub 与 enc——否则攻击者可以替换密文块、或把
        "谁发的"换一个人而签名依然有效。
        """
        d = self.to_dict()
        d.pop("signature", None)
        return json.dumps(d, ensure_ascii=False, sort_keys=True,
                          separators=(",", ":")).encode("utf-8")

    def aad_bytes(self) -> bytes:
        """加密的附加认证数据：只绑头部，不绑 payload/enc。

        目的：让"这条密文属于哪个会话、从谁到谁、什么时候过期"不可篡改。
        不绑 payload 是因为 payload 正是要加密的内容本身。
        """
        head = {
            "id": self.id, "from": self.from_agent,
            "to": {"type": self.to_type, "id": self.to_id},
            "act": self.act, "stage": self.stage,
            "conv": self.conversation_id, "trace": self.trace_id,
            "iat": int(self.created_at), "exp": int(self.expires_at),
            "ttl": self.ttl_hops,
        }
        return b"a2alink/v1/aad\x00" + json.dumps(
            head, sort_keys=True, separators=(",", ":")).encode("utf-8")

    @staticmethod
    def references_for(parent: "Envelope") -> List[str]:
        """给"回复 parent 的新消息"算 references。

        SMTP 是整条链全带。这里留**第一条 + 最近 N-1 条**：
        第一条是最初那个问题（排查时最想知道"从哪开始的"），中间那些
        转手记录在信封体积面前只能舍——但舍中间，不舍两头。
        """
        chain = list(parent.references) + [parent.id]
        if len(chain) > MAX_REFERENCES:
            chain = [chain[0]] + chain[-(MAX_REFERENCES - 1):]
        return chain

    def fingerprint(self) -> str:
        return hashlib.sha256(self.canonical_bytes()).hexdigest()[:16]

    # ---------------- 密码学 ----------------
    # 域分隔符：签名只对"信封"这一种结构有效。没有它，同一把私钥签出的
    # 字节可以在别的协议里被复用（跨协议签名伪造）。
    SIG_DOMAIN = b"a2alink/v1/envelope\x00"

    def sign(self, keystore: Any) -> None:
        """用本机私钥签名。必须先 seal_for() 再 sign()，顺序反了签名就废。"""
        from .crypto import b64e
        self.pub = {"alg": "ed25519+x25519",
                    "sign": keystore.signing.public_b64,
                    "kex": keystore.kex.public_b64}
        self.signature = b64e(keystore.sign(self.SIG_DOMAIN + self.canonical_bytes()))

    def verify(self, expected_sign_pub: Optional[bytes] = None) -> Dict[str, bytes]:
        """验签。返回对端公钥（sign/kex）。

        传入 expected_sign_pub 时做**公钥固定**比对——这一步才是真正
        防注册中心冒充的地方。只验"签名自洽"是没用的，因为攻击者可以
        自己生成一对密钥，签完把公钥一起发过来，自签自验永远通过。
        """
        from .crypto import (Ed25519KeyPair, KeyMismatchError, SignatureError,
                             b64d, fingerprint_of)
        if not self.signature:
            raise SignatureError("信封没有签名（对方可能用的是 0.1.x，或有人在剥离签名）")
        if not isinstance(self.pub, dict) or not self.pub.get("sign"):
            raise SignatureError("信封没有携带发送者公钥，无法验签")
        try:
            pub = b64d(self.pub["sign"])
            sig = b64d(self.signature)
        except Exception as e:
            raise SignatureError(f"公钥或签名编码非法: {e}") from e
        if len(pub) != 32 or len(sig) != 64:
            raise SignatureError("公钥或签名长度非法")
        if expected_sign_pub is not None and not hmac.compare_digest(pub, expected_sign_pub):
            raise KeyMismatchError(
                f"公钥与本地固定值不一致（收到 {fingerprint_of(pub)}，"
                f"本地 {fingerprint_of(expected_sign_pub)}）。"
                "这可能是对方换了钥匙，也可能是有人在冒充——先带外确认再更新。")
        if not Ed25519KeyPair.verify(pub, self.SIG_DOMAIN + self.canonical_bytes(), sig):
            raise SignatureError("签名校验失败：内容被改动，或发送者不是自称的那个人")
        kex = b64d(self.pub["kex"]) if self.pub.get("kex") else b""
        if kex and len(kex) != 32:
            raise SignatureError("交换公钥长度非法")
        return {"sign_pub": pub, "kex_pub": kex}

    def seal_payload(self, recipient_kex_pub: bytes) -> None:
        """把 payload 加密给指定接收方。加密后 payload 只剩占位符。"""
        from .crypto import encrypt_for
        plaintext = json.dumps(self.payload, ensure_ascii=False,
                               sort_keys=True).encode("utf-8")
        self.enc = encrypt_for(recipient_kex_pub, plaintext, self.aad_bytes())
        self.payload = {"_enc": True}

    def open_payload(self, my_kex: Any) -> Dict[str, Any]:
        """解密 payload。没加密就原样返回。"""
        from .crypto import DecryptionError, decrypt_from
        if not self.enc:
            return self.payload
        pt = decrypt_from(my_kex, my_kex.public_bytes, self.enc, self.aad_bytes())
        try:
            d = json.loads(pt.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as e:
            raise DecryptionError(f"解密成功但内容不是合法 JSON: {e}") from e
        if not isinstance(d, dict):
            raise DecryptionError("解密后的 payload 不是 object")
        return d

    def is_encrypted(self) -> bool:
        return bool(self.enc)

    def payload_text(self) -> str:
        """把载荷压成一段纯文本，供看门狗做指纹、供护栏做检测。"""
        parts: List[str] = []
        def walk(v: Any, depth: int = 0) -> None:
            if depth > 6:
                return
            if isinstance(v, str):
                parts.append(v)
            elif isinstance(v, dict):
                for k, vv in v.items():
                    parts.append(str(k))
                    walk(vv, depth + 1)
            elif isinstance(v, (list, tuple)):
                for vv in v:
                    walk(vv, depth + 1)
            elif v is not None:
                parts.append(str(v))
        walk(self.payload)
        return "\n".join(parts)

    # ---------------- 派生 ----------------
    def reply(self, from_agent: str, payload: Dict[str, Any], act: str = ACT_RESULT,
              stage: str = STAGE_DONE, **kw: Any) -> "Envelope":
        """构造回信：继承会话、递减 TTL、把用量写回预算。"""
        used = self.budget.used_messages + 1
        used_tokens = self.budget.used_tokens + estimate_tokens(self.payload_text())
        return Envelope(
            id=new_id(),
            from_agent=from_agent,
            to_type="agent",
            to_id=self.from_agent,
            act=act,
            stage=stage,
            payload=payload,
            conversation_id=self.conversation_id,
            in_reply_to=self.id,
            # 默认把"我"接进链里；转发场景可以显式传 references 覆盖。
            references=kw.pop("references", None) or self.references_for(self),
            correlation_id=self.correlation_id or self.id,
            idempotency_key=new_id("idem-"),
            created_at=time.time(),
            expires_at=min(self.expires_at, time.time() + 3600),
            ttl_hops=max(0, self.ttl_hops - 1),
            budget=Budget(self.budget.max_messages, self.budget.max_tokens, used, used_tokens),
            trace_id=self.trace_id,
            **kw,
        )

    def expired(self, now: Optional[float] = None) -> bool:
        return (now or time.time()) > self.expires_at

    # ---------------- 校验 ----------------
    @staticmethod
    def from_dict(d: Any) -> "Envelope":
        if not isinstance(d, dict):
            raise ProtocolError("envelope 必须是 object")
        if d.get("v") != PROTOCOL_VERSION:
            raise ProtocolError(f"不支持的协议版本: {d.get('v')!r}")

        def need_str(k: str, maxlen: int = 256) -> str:
            v = d.get(k)
            if not isinstance(v, str) or not v.strip():
                raise ProtocolError(f"缺少必填字段 {k}")
            if len(v) > maxlen:
                raise ProtocolError(f"{k} 超长")
            return v

        to = d.get("to")
        if not isinstance(to, dict):
            raise ProtocolError("to 必须是 object")
        to_type = to.get("type")
        if to_type not in ("agent", "group"):
            raise ProtocolError("to.type 只能是 agent / group")
        to_id = to.get("id")
        if not isinstance(to_id, str) or not to_id.strip() or len(to_id) > 256:
            raise ProtocolError("to.id 必填且长度 <= 256")

        act = d.get("act")
        if act not in ACTS:
            raise ProtocolError(f"未知 act: {act!r}")
        stage = d.get("stage", STAGE_OPEN)
        if stage not in STAGES:
            raise ProtocolError(f"未知 stage: {stage!r}")

        payload = d.get("payload")
        if not isinstance(payload, dict):
            raise ProtocolError("payload 必须是 object")

        pub = d.get("pub")
        if pub is not None:
            if not isinstance(pub, dict):
                raise ProtocolError("pub 必须是 object")
            s = pub.get("sign")
            k = pub.get("kex")
            if not isinstance(s, str) or len(s) > 128:
                raise ProtocolError("pub.sign 非法")
            if k is not None and (not isinstance(k, str) or len(k) > 128):
                raise ProtocolError("pub.kex 非法")

        enc = d.get("enc")
        if enc is not None:
            if not isinstance(enc, dict):
                raise ProtocolError("enc 必须是 object")
            for f in ("epk", "n", "ct", "tag"):
                v = enc.get(f)
                if not isinstance(v, str) or len(v) > 96 * 1024:
                    raise ProtocolError(f"enc.{f} 非法")
            if not isinstance(enc.get("alg"), str) or len(enc["alg"]) > 64:
                raise ProtocolError("enc.alg 非法")
            # 加密信封的 payload 应当是占位符。不是的话，说明有人在
            # "加密"的同时把明文也留在里面——典型的低级泄密事故。
            if payload and payload != {"_enc": True}:
                raise ProtocolError("信封同时带了密文和明文 payload，拒绝接收")

        def need_num(k: str) -> float:
            v = d.get(k)
            if not isinstance(v, (int, float)) or isinstance(v, bool) or v <= 0:
                raise ProtocolError(f"{k} 必须是正数")
            # JSON 标准里没有 Infinity/NaN，但 Python 的 json.loads **默认接受**
            # 它们（parse_constant）。不挡住的话，`"expires_at": Infinity`
            # 会让 expired() 永远返回 False —— 一条消息可以被无限期重放。
            if not math.isfinite(v):
                raise ProtocolError(f"{k} 必须是有限数（收到 {v!r}）")
            return float(v)

        ttl = d.get("ttl_hops")
        if not isinstance(ttl, int) or isinstance(ttl, bool) or ttl < 0:
            raise ProtocolError("ttl_hops 必须是非负整数")
        if ttl > MAX_HOPS_HARD_LIMIT:
            raise ProtocolError(f"ttl_hops 超过硬上限 {MAX_HOPS_HARD_LIMIT}")

        # capabilities 必须是字符串数组。以前是 `list(d.get(...) or [])`，
        # 于是 `"hack"` 会变成 ['h','a','c','k'] 静默通过——校验看着在做，
        # 实际做的是"把非法输入改造成合法输入"。
        caps_raw = d.get("capabilities")
        if caps_raw is None:
            caps_raw = []
        if not isinstance(caps_raw, list) or not all(isinstance(c, str) for c in caps_raw):
            raise ProtocolError("capabilities 必须是字符串数组")
        if len(caps_raw) > 64:
            raise ProtocolError("capabilities 条数过多")

        # 回复链：来源不可信，必须当外部输入校验。这里不做"超了就截断"的
        # 宽容处理——截断会把一条被篡改的链伪装成合法链，而排查时正是靠
        # 链的完整性判断"中间谁插过一手"。
        refs_raw = d.get("references")
        if refs_raw is None:
            refs_raw = []
        if not isinstance(refs_raw, list) or not all(isinstance(r, str) for r in refs_raw):
            raise ProtocolError("references 必须是字符串数组")
        if len(refs_raw) > MAX_REFERENCES:
            raise ProtocolError(f"references 超过 {MAX_REFERENCES} 条上限")
        for r in refs_raw:
            if not r.strip() or len(r) > 256:
                raise ProtocolError("references 里有空串或超长 ID")

        env = Envelope(
            id=need_str("id"),
            from_agent=need_str("from"),
            to_type=to_type,
            to_id=to_id,
            act=act,
            payload=payload,
            conversation_id=need_str("conversation_id"),
            created_at=need_num("created_at"),
            expires_at=need_num("expires_at"),
            ttl_hops=ttl,
            stage=stage,
            in_reply_to=d.get("in_reply_to"),
            references=list(refs_raw),
            correlation_id=d.get("correlation_id"),
            idempotency_key=d.get("idempotency_key"),
            budget=Budget.from_dict(d.get("budget")),
            capabilities=list(caps_raw),
            trace_id=d.get("trace_id"),
            signature=d.get("signature"),
            pub=pub,
            enc=enc,
        )
        if not isinstance(env.capabilities, list) or not all(isinstance(c, str) for c in env.capabilities):
            raise ProtocolError("capabilities 必须是字符串数组")
        if env.expires_at <= env.created_at:
            raise ProtocolError("expires_at 必须晚于 created_at")
        size = len(env.to_json().encode("utf-8"))
        if size > MAX_ENVELOPE_BYTES:
            raise ProtocolError(f"信封超过 {MAX_ENVELOPE_BYTES} 字节上限（{size}）")
        return env

    @staticmethod
    def from_json(s: str) -> "Envelope":
        try:
            # parse_constant 挡住 Infinity / -Infinity / NaN：
            # 标准 JSON 没有这三个字面量，但 Python 默认会把它们解析成 float。
            # 一条 expires_at=Infinity 的信封能永久绕过 TTL —— 见 need_num 的注释。
            d = json.loads(s, parse_constant=_reject_constant)
        except json.JSONDecodeError as e:
            raise ProtocolError(f"JSON 解析失败: {e}") from e
        except RecursionError as e:
            # 深度嵌套（例如 3000 层 `[`）在 json 解码阶段就会撞到 Python
            # 递归上限。这不是"格式错误"而是"输入太恶意"，但两者对调用方
            # 的处理方式相同：拒绝这条消息。绝不能让它逃逸成进程级崩溃。
            raise ProtocolError("JSON 嵌套层数过深") from e
        return Envelope.from_dict(d)


# --------------------------------------------------------------------------
# 便捷构造器
# --------------------------------------------------------------------------
def make_task(from_agent: str, to_id: str, instruction: str,
              to_type: str = "agent",
              conversation_id: Optional[str] = None,
              ttl_hops: int = 4,
              ttl_seconds: int = 600,
              max_messages: int = 12,
              max_tokens: int = 12000,
              capabilities: Optional[List[str]] = None,
              context: Optional[Dict[str, Any]] = None) -> Envelope:
    """派活。注意 ttl_hops 给 4，意思是"最多来回 4 跳"，不是 4 秒。"""
    now = time.time()
    cid = conversation_id or new_id("conv-")
    return Envelope(
        id=new_id(),
        from_agent=from_agent,
        to_type=to_type,
        to_id=to_id,
        act=ACT_TASK,
        payload={
            "instruction": instruction,
            "context": context or {},
            "expected": {"format": "json", "fields": ["status", "summary", "data"]},
        },
        conversation_id=cid,
        created_at=now,
        expires_at=now + ttl_seconds,
        ttl_hops=min(ttl_hops, MAX_HOPS_HARD_LIMIT),
        budget=Budget(max_messages=max_messages, max_tokens=max_tokens),
        capabilities=capabilities or [],
        trace_id=new_id("trace-"),
    )
