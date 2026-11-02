"""最小示例：本机起注册中心 + 两个 Agent 完成一次任务闭环。

运行：
    cd a2alink && PYTHONPATH=src python examples/two_agents.py

这个例子只做四件事，但把最容易写错的四处都摆出来了：
    1. 好友必须双向同意（服务端强制）
    2. 发消息要带 ttl_hops 和 budget（否则会无限往返）
    3. 收消息拿到的是"围栏化"文本，可直接进 prompt
    4. 回信必须显式 stage="done"（协议要求，不是礼貌）
"""

import os
import socket
import sys
import tempfile
import threading
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from a2alink import AgentLink
from a2alink.registry import Registry, make_server


def free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def main() -> None:
    tmp = tempfile.mkdtemp(prefix="a2alink-example-")
    port = free_port()
    reg = Registry(os.path.join(tmp, "db.sqlite3"))
    srv = make_server(reg, "127.0.0.1", port)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    url = f"http://127.0.0.1:{port}"
    time.sleep(0.2)

    ops = AgentLink(registry=url, name="ops", capabilities=["k8s", "logs"],
                    home=os.path.join(tmp, "ops"))
    research = AgentLink(registry=url, name="research", capabilities=["root-cause"],
                         home=os.path.join(tmp, "research"))

    # 1) 双向同意
    ops.friend_request("research", "线上告警，想请你一起看")
    rid = research.pending_requests()[0]["id"]
    research.friend_accept(rid)
    print("已是好友:", [f["peer"]["name"] for f in ops.friends()])

    # 2) 派活：ttl_hops 是"还能再转几手"，不是秒数
    sent = ops.send("research",
                    {"instruction": "nginx 大量 502，给我一个根因假设和验证步骤",
                     "context": {"symptom": "502 突增，持续 10 分钟"}},
                    ttl_hops=3, ttl_seconds=300, max_messages=6, max_tokens=4000)
    print("已发送:", sent.env.id, "跳数:", sent.env.ttl_hops)

    # 3) 收活：text 已经是围栏化内容
    batch = research.recv(wait=0)
    assert batch, "没有收到消息"
    got = batch[0]
    print("\n=== research 收到（可直接放入 prompt） ===")
    print(got.text)

    # 4) 回信并显式终止
    research.reply(got,
                   {"status": "ok",
                    "summary": "假设：上游 keepalive 超时小于后端处理时间，连接被复用后失败",
                    "data": {"confidence": 0.68,
                             "verify": ["看 upstream_response_time 分布",
                                        "对比 keepalive_timeout 与 P99 处理耗时"]}},
                   stage="done")
    print("research 已回信（stage=done）")

    back = ops.recv(wait=0)
    print("\n=== ops 收到结论 ===")
    print(back[0].text)

    print("\n看门狗统计:", ops.wd.stats())
    print("注册中心统计:", reg.stats())
    srv.shutdown()


if __name__ == "__main__":
    main()
