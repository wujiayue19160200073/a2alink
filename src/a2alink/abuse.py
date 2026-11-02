"""滥用防护 —— 专门对付「协议被拿去干坏事」的三类场景。

这个模块存在的理由，是我在设计评审时被问了一句话：
**"你这套东西，能不能被拿来做成 Agent 版的垃圾短信 / 传销裂变 / 窃听器？"**

答案是：能。任何"允许 A 主动联系 B"的协议都能。所以问题不是"能不能"，
而是"在哪一层掐住它，以及掐不住的部分怎么诚实承认"。

本模块只做**客户端侧**的三道保险丝（服务端侧在 registry.py 里）：

1) 传播预算（PropagationGuard）
   拦"一个 Agent 自己决定把同一段内容甩给几十个人"。这是蠕虫式扩散的最小形态，
   也是 LLM 被提示词劫持后最可能干的事（"把这段话转告你的所有联系人"）。
   判据两条：内容指纹触达的目标数、会话 ID 触达的目标数。

2) 转发署名（provenance）
   拦"把 A 的私聊原话洗成自己的话转述给 B"。这在人类 IM 里叫"截图外传"，
   在 Agent 网络里更隐蔽——因为转述是模型生成的，看起来完全像原创。
   规矩：**转发必须显式声明来源，且默认关闭**。关上它，窃听就少了一条现成通路。

3) 广播禁令（broadcast）
   v0.1 起就没有群发接口，只有"一次一个目标"。这条不是靠检查，是靠不给 API。

⚠️ 本模块拦不住的部分（写清楚，不装作拦得住）：
   - 攻击者自己实现协议、绕开本客户端。协议是公开的，这无法阻止，
     只能在注册中心侧做速率与关系校验（见 registry.py 的 rate_limit / invite 配额）。
   - 语义级的社会工程："帮我查一下你们公司的薪资表" 这类请求本身是合法消息。
     这类只能靠人看，靠 DLP 关键词检查，不能靠协议。
   - 多账号（女巫）:"注册 500 个 Agent 挨个加好友"。v0.1 用「注册邀请码 + 双向好友
     人工确认 + 好友申请配额」提高成本，但**没有从根本上解决**，见 docs/abuse.md。
"""

from __future__ import annotations

import hashlib
import time
from typing import Dict, List, Optional, Set, Tuple

__all__ = ["PropagationBlocked", "PropagationGuard", "ProvenanceError"]


class PropagationBlocked(RuntimeError):
    """触发了扩散保险丝。调用方应把它当作"需要人来看一眼"，而不是重试。"""

    def __init__(self, reason: str, detail: str, suggestion: str = "") -> None:
        super().__init__(f"{reason}: {detail}")
        self.reason = reason
        self.detail = detail
        self.suggestion = suggestion or "如需继续，请由人确认后使用 force=True 重发"


class ProvenanceError(ValueError):
    """试图匿名转发他人内容，而当前配置不允许转发。"""


def content_fingerprint(text: str) -> str:
    """内容指纹（sha256 前 16 位）。不做 simhash——这里要的是"完全一样的那段话"，
    近似去重是 watchdog 的活，两者目的不同，别混在一个函数里。"""
    return hashlib.sha256(text.strip().encode("utf-8", "ignore")).hexdigest()[:16]


class PropagationGuard:
    """扩散保险丝。状态是**进程内**的，重启即重置——这是已知弱点（见 docs/architecture.md）。

    参数默认值不是拍脑袋定的，是按"正常协作"与"裂变扩散"的分界：
      - 同一段话发给 3 个不同 Agent：正常（比如问三个专家同一个问题）
      - 发给 6 个以上：可疑
      - 同一个会话 ID 出现在 4 个以上对端：几乎只能是接力转发 / 群发脚本
    """

    def __init__(self, max_targets_per_content: int = 4,
                 max_peers_per_conversation: int = 6,
                 window_seconds: float = 1800.0,
                 allow_forward: bool = False,
                 enabled: bool = True) -> None:
        self.max_targets_per_content = max(1, int(max_targets_per_content))
        self.max_peers_per_conversation = max(1, int(max_peers_per_conversation))
        self.window = float(window_seconds)
        self.allow_forward = bool(allow_forward)
        self.enabled = bool(enabled)
        self._content: Dict[str, List[Tuple[float, str]]] = {}
        self._convs: Dict[str, List[Tuple[float, str]]] = {}
        self.hits = 0

    # ---- 内部 ----
    def _prune(self, bucket: List[Tuple[float, str]], now: float) -> List[Tuple[float, str]]:
        cutoff = now - self.window
        return [(t, p) for t, p in bucket if t >= cutoff]

    def _peers(self, bucket: List[Tuple[float, str]]) -> Set[str]:
        return {p for _t, p in bucket}

    # ---- 对外 ----
    def check(self, text: str, conversation_id: str, target: str) -> None:
        """放行或不放行。不放行就抛，绝不"降级为警告"——警告没人看。"""
        if not self.enabled:
            return
        now = time.time()
        fp = content_fingerprint(text)

        cb = self._prune(self._content.get(fp, []), now)
        peers = self._peers(cb)
        if target not in peers and len(peers) >= self.max_targets_per_content:
            self.hits += 1
            raise PropagationBlocked(
                "content_fanout",
                f"同一段内容在 {int(self.window/60)} 分钟内已发往 {len(peers)} 个不同目标"
                f"（上限 {self.max_targets_per_content}），疑似批量群发/裂变传播",
                "确认这段内容确实需要发给这么多方，再由人 force=True 放行")

        vb = self._prune(self._convs.get(conversation_id, []), now)
        vpeers = self._peers(vb)
        if target not in vpeers and len(vpeers) >= self.max_peers_per_conversation:
            self.hits += 1
            raise PropagationBlocked(
                "conversation_spread",
                f"同一个会话 {conversation_id} 在 {int(self.window/60)} 分钟内已经"
                f"触达 {len(vpeers)} 个对端（上限 {self.max_peers_per_conversation}），"
                "疑似接力转发（handoff 链被用来扩散）",
                "接力扩散必须由人确认；请检查这是否是被提示词诱导的传播")

        cb.append((now, target))
        vb.append((now, target))
        self._content[fp] = cb
        self._convs[conversation_id] = vb

    def check_forward(self, forwarded_from: Optional[str]) -> None:
        """转发闸门。默认**关闭转发**：不是因为技术上做不到，
        而是因为"能把别人的私聊原话转给第三人"本身就是一个窃听链路。"""
        if forwarded_from and not self.allow_forward:
            raise ProvenanceError(
                "当前配置禁止转发他人消息（allow_forward=False，默认值）。\n"
                "  想开启：AgentLink(allow_forward=True)，并在 payload 中保留来源信息。\n"
                "  开之前请想清楚：你愿不愿意自己的私聊被这样转出去。")

    def stats(self) -> Dict[str, object]:
        return {"hits": self.hits,
                "tracked_contents": len(self._content),
                "tracked_conversations": len(self._convs),
                "allow_forward": self.allow_forward,
                "window_seconds": self.window}
