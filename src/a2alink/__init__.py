"""A2A Link —— 让不同框架的 AI Agent 在同一个协议下互相找到、互相信任、互相干活。

最小的用法：

    from a2alink import AgentLink

    me = AgentLink(name="ops-agent", capabilities=["k8s", "alert-triage"])
    me.friend_request("research-agent", "想请你帮我查一下这个告警的根因")
    me.send("research-agent", {"instruction": "查一下磁盘告警的常见根因"})

⚠️ 安全提醒：本库会让你的 Agent 与外网 Agent 通信。发出去的内容会先过
出站 DLP 闸门（内网IP/域名/密钥/身份信息默认拦下），但闸门只兜已知形态，
业务数据是否可出域必须由人判断。上线前请读 SECURITY.md。
"""

from .protocol import (ACT_EVENT, ACT_NOTICE, ACT_RESULT, ACT_TASK, Budget,
                       Envelope, ProtocolError, make_task, new_id)
from .watchdog import STOP, Watchdog, simhash
from .guard import (ALLOW, BLOCK, REDACT, EgressGuard, IngressGuard,
                    compliance_report)
from .abuse import PropagationBlocked, PropagationGuard, ProvenanceError
from .client import (AgentLink, EgressBlocked, LinkError, LoopHalt, Received, Sent)
from .adapters import (AutoGenAdapter, DeepSeekHarnessAdapter, EchoAdapter,
                       LLMAdapter, TOOL_SPECS, bind_tools, parse_reply)
from .registry import Registry, make_server, serve

__version__ = "0.1.1"

__all__ = [
    "AgentLink", "EgressBlocked", "LinkError", "LoopHalt", "Received", "Sent",
    "Envelope", "Budget", "ProtocolError", "make_task", "new_id",
    "Watchdog", "simhash", "STOP",
    "EgressGuard", "IngressGuard", "compliance_report", "ALLOW", "BLOCK", "REDACT",
    "PropagationGuard", "PropagationBlocked", "ProvenanceError",
    "EchoAdapter", "LLMAdapter", "DeepSeekHarnessAdapter", "AutoGenAdapter",
    "TOOL_SPECS", "bind_tools", "parse_reply",
    "Registry", "serve", "make_server",
    "ACT_TASK", "ACT_RESULT", "ACT_EVENT", "ACT_NOTICE",
    "__version__",
]
