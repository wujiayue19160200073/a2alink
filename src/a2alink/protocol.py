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
import json
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

_CJK = re.compile(r"[\u3400-\u4dbf\u4e00-\u9fff\u3040-\u30ff\uac00-\ud7af]")


class ProtocolError(ValueError):
    """信封格式非法。上层应视为攻击面，按不可信输入处理。"""


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
    correlation_id: Optional[str] = None
    idempotency_key: Optional[str] = None
    budget: Budget = field(default_factory=Budget)
    capabilities: List[str] = field(default_factory=list)  # 本条消息请求的能力
    trace_id: Optional[str] = None
    signature: Optional[str] = None
    v: str = PROTOCOL_VERSION

    # ---------------- 序列化 ----------------
    def to_dict(self) -> Dict[str, Any]:
        return {
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
            "signature": self.signature,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False, separators=(",", ":"))

    def canonical_bytes(self) -> bytes:
        """签名用字节流：排除 signature 本身，字段顺序固定。"""
        d = self.to_dict()
        d.pop("signature", None)
        return json.dumps(d, ensure_ascii=False, sort_keys=True,
                          separators=(",", ":")).encode("utf-8")

    def fingerprint(self) -> str:
        return hashlib.sha256(self.canonical_bytes()).hexdigest()[:16]

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

        def need_num(k: str) -> float:
            v = d.get(k)
            if not isinstance(v, (int, float)) or isinstance(v, bool) or v <= 0:
                raise ProtocolError(f"{k} 必须是正数")
            return float(v)

        ttl = d.get("ttl_hops")
        if not isinstance(ttl, int) or isinstance(ttl, bool) or ttl < 0:
            raise ProtocolError("ttl_hops 必须是非负整数")
        if ttl > MAX_HOPS_HARD_LIMIT:
            raise ProtocolError(f"ttl_hops 超过硬上限 {MAX_HOPS_HARD_LIMIT}")

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
            correlation_id=d.get("correlation_id"),
            idempotency_key=d.get("idempotency_key"),
            budget=Budget.from_dict(d.get("budget")),
            capabilities=list(d.get("capabilities") or []),
            trace_id=d.get("trace_id"),
            signature=d.get("signature"),
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
            d = json.loads(s)
        except json.JSONDecodeError as e:
            raise ProtocolError(f"JSON 解析失败: {e}") from e
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
