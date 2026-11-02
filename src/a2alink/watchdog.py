"""循环治理看门狗（Watchdog）—— 本项目真正的护城河。

======================= 为什么"加个轮次上限"不够 =======================
绝大多数 A2A 原型的看门狗是这么写的：

    if round > 10: break

这在单机、单会话、两人对话里能work。一旦上公网，你会遇到这五种死法：

 1) **TTL 不递减**：A 发给 B，B 转给 C，C 再回给 A。每条链路的 round 都是 1，
    轮次上限永远不触发，token 在网络上绕圈烧。→ 必须用信封级的 hop 递减。
 2) **语义空转**：两个 Agent 客客气气地"收到""明白了""那我再确认一下"，
    每句话都是新的、轮次也在涨，但信息量为零。→ 必须做内容指纹去重。
 3) **礼貌性互推**：A 说"麻烦你确认"，B 说"请你先确认"，无限推让。
    → 必须做 ping-pong 模式检测。
 4) **群聊扇出**：10 人群，一条消息 10 个收件人各回 1 条 = 100 条。
    轮次只涨了 1，消息量涨了 100 倍。→ 必须按"收件人"计数，不是按"轮次"。
 5) **预算分裂**：每次转手都新建一个 Budget，预算永远重置。
    → 预算必须随信封继承并递减，由发送方"预付"。

所以本看门狗是三件事的乘积：
    递减量（hop / budget） × 内容指纹（simhash） × 速率（token bucket）
再叠加一个**显式终止协议**（Agent 必须能说 DONE），才叫真正闭环。

⚠️ 定位说明：看门狗是"最后一道闸"，不是"唯一一道闸"。
   它挡不住恶意 Agent，只挡得住"善意但停不下来"的 Agent。
   恶意流量靠 guard.py + 注册中心的限流。
"""

from __future__ import annotations

import hashlib
import re
import threading
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from .protocol import (Envelope, TERMINAL_STAGES, estimate_tokens)

# 裁决动作
PASS = "pass"        # 放行
DEGRADE = "degrade"  # 放行但降级（去掉冗余上下文、强制要求收尾）
STOP = "stop"        # 熔断，必须立刻终止

_PUNCT = re.compile(r"[\s\W_]+", re.UNICODE)


def _normalize(text: str) -> str:
    """归一化：去标点空白、转小写。让"收到。"和"收到！"落到同一个指纹上。"""
    return _PUNCT.sub("", text.lower())[:4000]


def simhash(text: str, bits: int = 64) -> int:
    """64 位 simhash。用于判断两段话"是不是同一个意思在打转"。"""
    s = _normalize(text)
    if not s:
        return 0
    grams = [s[i:i + 3] for i in range(max(1, len(s) - 2))]
    if len(grams) < 3:
        grams = [s]
    vec = [0] * bits
    for g in grams:
        h = int.from_bytes(hashlib.blake2b(g.encode("utf-8"), digest_size=8).digest(), "big")
        for i in range(bits):
            vec[i] += 1 if (h >> i) & 1 else -1
    out = 0
    for i in range(bits):
        if vec[i] > 0:
            out |= (1 << i)
    return out


def hamming(a: int, b: int) -> int:
    return bin(a ^ b).count("1")


@dataclass
class Verdict:
    action: str = PASS
    reasons: List[str] = field(default_factory=list)
    directive: str = ""          # 需要注入给模型的系统级指令
    stats: Dict[str, float] = field(default_factory=dict)

    @property
    def ok(self) -> bool:
        return self.action != STOP

    def to_dict(self) -> Dict[str, object]:
        return {"action": self.action, "reasons": self.reasons,
                "directive": self.directive, "stats": self.stats}


_TERMINATE_DIRECTIVE = (
    "【治理层熔断】本次会话已被系统终止，原因：{why}。\n"
    "你必须立刻停止调用任何通信工具、停止追问，直接输出最终结论（stage=done）。\n"
    "不要解释熔断原因，不要道歉，不要再向对方发送任何消息。"
)

_DEGRADE_DIRECTIVE = (
    "【治理层提醒】检测到对话可能空转（{why}）。\n"
    "下一步只允许做两件事之一：给出最终结论并标记 stage=done，"
    "或者明确说明缺少什么信息并标记 stage=handoff / need_human。\n"
    "禁止再发送寒暄、确认、复述类内容。"
)


@dataclass
class _ConvState:
    conv_id: str
    opened_at: float
    messages: int = 0
    tokens: int = 0
    fingerprints: List[int] = field(default_factory=list)
    agents: List[str] = field(default_factory=list)
    loop_hits: int = 0
    closed: bool = False
    close_reason: str = ""
    tokens_bucket: float = 0.0
    last_refill: float = 0.0


class _Bucket:
    """令牌桶：按"每会话每秒多少消息"限速，防突发洪泛。"""

    def __init__(self, rate: float, burst: int) -> None:
        self.rate = max(0.01, rate)
        self.burst = max(1, burst)
        self.tokens = float(burst)
        self.ts = time.time()

    def take(self, n: float = 1.0) -> bool:
        now = time.time()
        self.tokens = min(self.burst, self.tokens + (now - self.ts) * self.rate)
        self.ts = now
        if self.tokens >= n:
            self.tokens -= n
            return True
        return False

    def penalty(self, seconds: float) -> None:
        self.tokens = max(-self.burst, self.tokens - self.rate * seconds)


class Watchdog:
    """三合一循环治理器。一个进程一个实例，可复用于任意多会话。"""

    def __init__(self,
                 max_messages: int = 20,
                 max_tokens: int = 20000,
                 max_wall_seconds: float = 600.0,
                 max_conversations: int = 512,
                 loop_distance: int = 3,
                 loop_hits_to_stop: int = 2,
                 rate: float = 0.5,
                 burst: int = 6,
                 fanout_extra: int = 0) -> None:
        self.max_messages = max_messages
        self.max_tokens = max_tokens
        self.max_wall_seconds = max_wall_seconds
        self.max_conversations = max_conversations
        self.loop_distance = loop_distance
        self.loop_hits_to_stop = loop_hits_to_stop
        self.rate = rate
        self.burst = burst
        self.fanout_extra = fanout_extra      # 群聊允许的额外扇出系数
        self._convs: Dict[str, _ConvState] = {}
        self._buckets: Dict[str, _Bucket] = {}
        self._lock = threading.RLock()
        self.counters = {"passed": 0, "degraded": 0, "stopped": 0}

    # ---------------- 对外主入口 ----------------
    def check_outbound(self, env: Envelope) -> Verdict:
        return self._evaluate(env, direction="out")

    def check_inbound(self, env: Envelope) -> Verdict:
        return self._evaluate(env, direction="in")

    def close(self, conversation_id: str, reason: str = "explicit") -> None:
        with self._lock:
            st = self._convs.get(conversation_id)
            if st:
                st.closed = True
                st.close_reason = reason

    def stats(self) -> Dict[str, object]:
        with self._lock:
            return {
                "counters": dict(self.counters),
                "conversations": len(self._convs),
                "active": sum(1 for s in self._convs.values() if not s.closed),
            }

    def reset(self, conversation_id: Optional[str] = None) -> None:
        with self._lock:
            if conversation_id is None:
                self._convs.clear()
                self._buckets.clear()
            else:
                self._convs.pop(conversation_id, None)
                self._buckets.pop(conversation_id, None)

    # ---------------- 核心判定 ----------------
    def _evaluate(self, env: Envelope, direction: str) -> Verdict:
        now = time.time()
        reasons: List[str] = []

        # 1) 信封本身是否已经过期 / hop 是否用完
        if env.expired(now):
            return self._result(STOP, ["信封已过期 (expires_at < now)"], "ttl_expired")
        if env.ttl_hops <= 0:
            return self._result(STOP, ["跳数耗尽 ttl_hops=0（链路已到末端）"], "hop_exhausted")

        # 2) 这条会话是否已经在别处被判定终止
        budget = env.budget
        if budget.exhausted():
            return self._result(STOP, ["信封携带的预算已耗尽（发送方预付额度用完）"], "budget_exhausted")

        with self._lock:
            st = self._convs.get(env.conversation_id)
            if st is None:
                if len(self._convs) >= self.max_conversations:
                    self._evict_oldest()
                st = _ConvState(conv_id=env.conversation_id, opened_at=now)
                self._convs[env.conversation_id] = st

            if st.closed:
                return self._result(STOP, [f"会话已终止: {st.close_reason or 'closed'}"], "conversation_closed")

            # 3) 显式终止信号：Agent 说 DONE 之后，任何人都不得再往这条会话写
            if env.stage in TERMINAL_STAGES and direction == "out":
                st.closed = True
                st.close_reason = f"peer_declared_{env.stage}"
                self.counters["passed"] += 1
                return self._result(PASS, [f"对端显式终止: {env.stage}"], "")

            est = estimate_tokens(env.payload_text())

            # 4) 速率：先看单会话桶
            b = self._buckets.get(env.conversation_id)
            if b is None:
                b = _Bucket(self.rate, self.burst)
                self._buckets[env.conversation_id] = b
            if not b.take():
                b.penalty(5)
                self.counters["stopped"] += 1
                return self._result(STOP, ["会话速率超限（疑似洪泛/死循环）"], "rate_limited")

            # 5) 三重配额：消息数按"收件人数"计，token 按累计
            fanout = 1 + self.fanout_extra if env.to_type == "group" else 1
            st.messages += fanout
            st.tokens += est
            st.agents.append(env.from_agent)

            if st.messages > self.max_messages:
                st.closed = True
                st.close_reason = "message_quota"
                self.counters["stopped"] += 1
                return self._result(STOP, [f"消息配额超限 {st.messages}>{self.max_messages}"], "message_quota")
            if st.tokens > self.max_tokens:
                st.closed = True
                st.close_reason = "token_quota"
                self.counters["stopped"] += 1
                return self._result(STOP, [f"token 预算超限 {st.tokens}>{self.max_tokens}"], "token_quota")
            if (now - st.opened_at) > self.max_wall_seconds:
                st.closed = True
                st.close_reason = "wall_clock"
                self.counters["stopped"] += 1
                return self._result(STOP, [f"会话时长超限 {now - st.opened_at:.0f}s"], "wall_clock")

            # 6) 内容指纹：语义空转检测（这是轮次上限挡不住的那一类）
            fp = simhash(env.payload_text())
            dup = [hamming(fp, old) for old in st.fingerprints[-8:]]
            closest = min(dup) if dup else 64
            if closest <= self.loop_distance:
                st.loop_hits += 1
                if st.loop_hits >= self.loop_hits_to_stop:
                    st.closed = True
                    st.close_reason = "content_loop"
                    self.counters["stopped"] += 1
                    return self._result(
                        STOP,
                        [f"内容空转：与历史消息指纹距离 {closest}（阈值 {self.loop_distance}），第 {st.loop_hits} 次"],
                        "content_loop")
                self.counters["degraded"] += 1
                return self._result(
                    DEGRADE,
                    [f"疑似复述，指纹距离 {closest}"],
                    "near_duplicate", directive=_DEGRADE_DIRECTIVE.format(why="内容与历史高度重复"))
            st.fingerprints.append(fp)
            if len(st.fingerprints) > 32:
                st.fingerprints = st.fingerprints[-32:]

            # 7) 礼貌性互推：A→B→A→B 且每步信息量都很小
            if self._pingpong(st.agents, est):
                st.loop_hits += 1
                if st.loop_hits >= self.loop_hits_to_stop:
                    st.closed = True
                    st.close_reason = "pingpong"
                    self.counters["stopped"] += 1
                    return self._result(STOP, ["检测到礼貌性互推死循环"], "pingpong")
                self.counters["degraded"] += 1
                return self._result(DEGRADE, ["疑似互推"], "pingpong",
                                    directive=_DEGRADE_DIRECTIVE.format(why="双方在互相要求对方先行动"))

            # 8) 快烧完了提前预警，而不是等到最后一刻硬断
            #    注意：只有当"还没满"时才算预警；已经满了下一条会被配额直接拦，
            #    这里再报一次降级只是噪音。
            left = min(1.0 - st.messages / max(1, self.max_messages),
                       1.0 - st.tokens / max(1, self.max_tokens))
            if left < 0.2 and st.messages < self.max_messages and st.tokens < self.max_tokens:
                self.counters["degraded"] += 1
                return self._result(
                    DEGRADE,
                    [f"配额余量不足 20%（消息 {st.messages}/{self.max_messages}，"
                     f"token {st.tokens}/{self.max_tokens}）"],
                    "budget_low",
                    directive=_DEGRADE_DIRECTIVE.format(why="会话预算即将耗尽"))

            self.counters["passed"] += 1
            return Verdict(PASS, reasons, "", {
                "messages": st.messages, "tokens": st.tokens,
                "budget_ratio": round(1.0 - left, 3),
            })

    # ---------------- 辅助 ----------------
    def _pingpong(self, agents: List[str], est: int) -> bool:
        if len(agents) < 6 or est > 80:
            return False
        tail = agents[-6:]
        a, b = tail[0], tail[1]
        if a == b:
            return False
        return all(tail[i] == (a if i % 2 == 0 else b) for i in range(6))

    def _evict_oldest(self) -> None:
        if not self._convs:
            return
        oldest = min(self._convs.values(), key=lambda s: s.opened_at)
        self._convs.pop(oldest.conv_id, None)
        self._buckets.pop(oldest.conv_id, None)

    def _result(self, action: str, reasons: List[str], why: str,
                directive: str = "") -> Verdict:
        if action == STOP and not directive:
            directive = _TERMINATE_DIRECTIVE.format(why=why)
        return Verdict(action=action, reasons=reasons, directive=directive)


# 方便调用方做"给模型看的提示词"组装
def compose_guard_notice(verdicts: List[Verdict]) -> str:
    parts = [v.directive for v in verdicts if v.directive]
    return "\n\n".join(dict.fromkeys(parts))
