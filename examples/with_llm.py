"""接真模型的示例（这里用一个假的 llm 函数，方便离线跑通）。

真实接入时只要替换 `fake_llm`：

    # DeepSeek Harness
    adapter = DeepSeekHarnessAdapter(lambda p: harness.run(p).text)

    # OpenAI 兼容接口（vLLM / Ollama / DeepSeek 官方）
    from openai import OpenAI
    cli = OpenAI(base_url=..., api_key=...)
    def llm(prompt: str) -> str:
        return cli.chat.completions.create(
            model="deepseek-chat",
            messages=[{"role": "user", "content": prompt}],
            temperature=0.2,
        ).choices[0].message.content
    adapter = LLMAdapter(llm, system="你是运维专家 Agent")

⚠️ 注意：接上真模型之后，Agent 就有了"自由发挥"的能力，包括：
   - 把本地配置里的内容写进回复（出站 DLP 会拦已知形态，拦不住业务语义）
   - 被对端几句话说服去"顺手查一下"某些东西
   所以 system prompt 里的 LOOP_CONTRACT（adapters.py 自动拼上）不要删，
   并且出事时第一件事是看它对不对端的要求做了不该做的事。

运行：
    cd a2alink && PYTHONPATH=src python examples/with_llm.py
"""

import json
import os
import socket
import sys
import tempfile
import threading
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from a2alink import AgentLink
from a2alink.adapters import LLMAdapter, build_prompt
from a2alink.registry import Registry, make_server


def fake_llm(prompt: str) -> str:
    """假装是一个模型：始终回一个合规的 JSON，并显式声明 done。"""
    assert "<untrusted_external_content" in prompt, "围栏丢失了，别上线"
    return json.dumps({
        "status": "ok",
        "summary": "看起来是上游限流导致的 502，建议加指数退避并观察 P99",
        "data": {"confidence": 0.6},
        "stage": "done",
    }, ensure_ascii=False)


def free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def main() -> None:
    tmp = tempfile.mkdtemp(prefix="a2alink-llm-")
    port = free_port()
    reg = Registry(os.path.join(tmp, "db.sqlite3"))
    srv = make_server(reg, "127.0.0.1", port)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    url = f"http://127.0.0.1:{port}"
    time.sleep(0.2)

    a = AgentLink(registry=url, name="asker", home=os.path.join(tmp, "asker"))
    b = AgentLink(registry=url, name="answerer", capabilities=["analysis"],
                  home=os.path.join(tmp, "answerer"))

    a.friend_request("answerer", "问个问题")
    b.friend_accept(b.pending_requests()[0]["id"])

    a.send("answerer", {"instruction": "502 突增，最可能的三个原因是什么？"})

    adapter = LLMAdapter(fake_llm, system="你是资深 SRE。")
    stats = b.run(adapter.handle, poll=0.5, max_rounds=5)
    print("answerer 处理结果:", stats)

    got = a.recv(wait=0)
    print("\n=== asker 收到 ===")
    print(got[0].text)

    # 也可以手动拼一次 prompt，看看模型到底看到了什么（排查注入时很有用）
    print("\n=== 模型实际收到的 prompt（节选）===")
    print(build_prompt("你是资深 SRE。", got[0])[:600])

    srv.shutdown()


if __name__ == "__main__":
    main()
