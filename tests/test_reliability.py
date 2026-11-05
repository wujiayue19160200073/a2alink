"""可靠投递测试：已读 != 做完，失败会重投，重投用尽进死信，掉线能留遗嘱。

这个文件针对的是一类**静默故障**：任务消失了，但日志上一切正常。
以前"读了"就等当地"做完了"，于是三种真实情况——Agent 读完崩溃、
读完转手给别人、读完发现自己做不了——在审计链上都是一个样子：
什么都没有。查不到，也就没人需要负责。
"""

import os
import socket
import sys
import tempfile
import threading
import time
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from a2alink.client import AgentLink
from a2alink.protocol import MAX_REFERENCES, Envelope, ProtocolError
from a2alink.registry import Registry, make_server


# 测试绝不能写进真实的 ~/.a2alink。
# 出站闸门判 BLOCK 时默认会把内容挂进审批队列，而测试用例里
# 故意带着"密钥"形态的字符串——一次跑测试就在用户目录里留下一堆
# 待批的假机密，还会让 `approvals list` 和审计报告失真。
os.environ.setdefault("A2ALINK_HOME", tempfile.mkdtemp(prefix="a2a-test-"))



def free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def boot(max_attempts: int = 3):
    tmp = tempfile.mkdtemp(prefix="a2a-rel-")
    port = free_port()
    reg = Registry(os.path.join(tmp, "t.sqlite3"), local_mesh=True,
                   max_attempts=max_attempts)
    srv = make_server(reg, "127.0.0.1", port)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    time.sleep(0.12)
    url = f"http://127.0.0.1:{port}"
    a = AgentLink(registry=url, name="rel-a", home=os.path.join(tmp, "a"))
    b = AgentLink(registry=url, name="rel-b", home=os.path.join(tmp, "b"))
    return reg, srv, a, b, tmp


class _Base(unittest.TestCase):
    def setUp(self):
        self.reg, self.srv, self.a, self.b, self.tmp = boot()

    def tearDown(self):
        try:
            self.srv.shutdown()
            self.srv.server_close()
        finally:
            self.reg.conn.close()

    def send_one(self) -> str:
        self.a.send_text(self.b.agent_id, "跑一下回归", act="task")
        got = self.b.recv(wait=3)
        self.assertTrue(got, "消息没投递到")
        return got[0].env.id


class TestReferencesChain(unittest.TestCase):
    """回复链：加字段绝不能让老信封的签名失效。"""

    @staticmethod
    def env(**kw) -> Envelope:
        now = time.time()
        base = dict(id="m" * 32, from_agent="agt-a", to_type="agent",
                    to_id="agt-b", act="task", payload={"instruction": "hi"},
                    conversation_id="conv-1", created_at=now,
                    expires_at=now + 60, ttl_hops=3)
        base.update(kw)
        return Envelope(**base)

    def test_empty_chain_keeps_old_bytes(self):
        """空链时规范字节里不能出现 references。

        这是兼容性红线：canonical_bytes 直接序列化 to_dict()，
        只要多一个 "references": []，0.3 时代所有信封的签名会集体失效——
        一次"加功能"就变成"历史消息全部不认"。
        """
        e = self.env()
        self.assertNotIn("references", e.to_dict())
        self.assertNotIn(b"references", e.canonical_bytes())
        # 即便对方显式传了空数组，往返之后也必须被规范回"不落字段"
        dirty = dict(e.to_dict(), references=[])
        self.assertNotIn("references", Envelope.from_dict(dirty).to_dict())

    def test_chain_grows_and_keeps_both_ends(self):
        prev = self.env()
        for i in range(20):
            n = self.env(id=f"x{i:02d}" + "0" * 29)
            n.references = Envelope.references_for(prev)
            prev = n
        self.assertEqual(len(prev.references), MAX_REFERENCES)
        self.assertIn("m" * 32, prev.references, "最早的那条（最初的问题）不能丢")
        # references 是"我回复过谁"，天然不含自己；最后一条是上一跳
        self.assertEqual(prev.references[-1], "x18" + "0" * 29)

    def test_oversized_chain_is_rejected(self):
        # 不截断。截断会把一条被篡改过的链伪装成合法链，
        # 而排查时判断"中间谁插过一手"全靠链的完整性。
        d = self.env().to_dict()
        d["references"] = ["z" * 8] * (MAX_REFERENCES + 1)
        with self.assertRaises(ProtocolError):
            Envelope.from_dict(d)


class TestDeliverySemantics(_Base):
    def test_recv_alone_is_not_done(self):
        """整次改动的核心断言：收信不等于完成。"""
        self.send_one()
        self.assertEqual(self.b.inflight()["count"], 1)

    def test_done_clears_inflight(self):
        mid = self.send_one()
        self.assertEqual(self.b.done(mid)["done"], 1)
        self.assertEqual(self.b.inflight()["count"], 0)

    def test_fail_requeues_then_dead_letters(self):
        mid = self.send_one()
        for i in range(2):
            out = self.b.fail(mid, reason=f"第{i + 1}次超时")
            self.assertFalse(out["dead"])
            self.assertTrue(out["requeued"])
            again = self.b.recv(wait=3)
            self.assertTrue(again, "重投之后应该能再次收到")
            self.assertEqual(again[0].env.id, mid)
        out = self.b.fail(mid, reason="第三次")
        self.assertTrue(out["dead"])
        self.assertFalse(out["requeued"])
        self.assertEqual(self.b.dlq()["count"], 1)
        # 进死信的消息不该再出现在 inflight 里（否则会被反复捡起来）
        self.assertEqual(self.b.inflight()["count"], 0)

    def test_dlq_requeue_then_purge(self):
        mid = self.send_one()
        for _ in range(3):
            self.b.fail(mid, reason="坏了")
        self.assertEqual(self.b.dlq()["count"], 1)

        self.b.dlq_requeue(mid)
        self.assertEqual(self.b.dlq()["count"], 0)
        self.assertTrue(self.b.recv(wait=3), "重投后应该重新回到队列")
        self.b.done(mid)
        self.assertEqual(self.b.inflight()["count"], 0)

    def test_cannot_fail_someone_elses_message(self):
        """拿别人的消息 ID 刷失败计数、或把别人的消息推进死信，必须被拒。"""
        mid = self.send_one()
        with self.assertRaises(Exception):
            self.a.fail(mid, reason="我没收到过这条")

    def test_inflight_only_shows_latest_delivery(self):
        """重投过三次也是**一件事**，不能报成三件。"""
        mid = self.send_one()
        self.b.fail(mid, reason="1")
        self.b.recv(wait=3)
        self.b.fail(mid, reason="2")
        self.b.recv(wait=3)
        self.assertEqual(self.b.inflight()["count"], 1)


class TestLastWill(_Base):
    def test_fires_once_after_timeout(self):
        out = self.a.set_will(self.b.agent_id, "我掉线了，回归没跑完", ttl_seconds=60)
        self.assertTrue(out["will"])
        self.assertEqual(self.reg.sweep_wills(), [], "刚立完不该触发")

        fired = self.reg.sweep_wills(now=time.time() + 120)
        self.assertEqual(len(fired), 1)
        self.assertTrue(fired[0]["fired"])

        got = self.b.recv(wait=3)
        self.assertTrue(got)
        self.assertEqual(got[0].env.act, "notice")
        self.assertTrue(got[0].authenticated, "遗嘱也必须验签通过")
        self.assertIn("掉线", got[0].text or "")

        # 一个 Agent 只能"死"一次。否则每轮巡检都发一遍，遗嘱就成了消息风暴。
        self.assertEqual(self.reg.sweep_wills(now=time.time() + 300), [])

    def test_clear_prevents_firing(self):
        self.a.set_will(self.b.agent_id, "我不在了", ttl_seconds=60)
        self.a.clear_will()
        self.assertEqual(self.reg.sweep_wills(now=time.time() + 120), [])
        self.assertFalse(self.b.recv(wait=1))

    def test_will_must_carry_owner_signature(self):
        """服务端没有私钥，所以它造不出一条能过验签的遗嘱。

        这正是为什么遗嘱必须"客户端预签、服务端保管"——
        一旦允许服务端临时生成，接收方要么拒收，要么为遗嘱开一个
        不验签的降级口子，而那个口子迟早会被用来伪造。
        """
        now = time.time()
        env = Envelope(id="f" * 32, from_agent=self.a.agent_id,
                       to_type="agent", to_id=self.b.agent_id,
                       act="notice", stage="done",
                       payload={"instruction": "伪造的遗嘱"},
                       conversation_id="conv-x", created_at=now,
                       expires_at=now + 600, ttl_hops=1)
        with self.assertRaises(Exception):
            self.reg.set_will(self.a.agent_id, env, 60)

    def test_ttl_bounds(self):
        with self.assertRaises(Exception):
            self.a.set_will(self.b.agent_id, "x", ttl_seconds=5)


if __name__ == "__main__":
    unittest.main()
