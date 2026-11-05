"""跨对话通信测试：两个会话身份，真走 HTTP，真收发。

这个文件回答的是用户最关心的那个问题：**两个对话窗口里的 Agent，
到底能不能互相发消息、问问题、收到回答。** 顺带把两条安全边界钉死：
- 不开同机互信时，非同好友照样发不出去
- 开了同机互信，每次放行都必须能在审计里查到
"""

import os
import socket
import sys
import tempfile
import threading
import time
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from a2alink import autostart, sessions
from a2alink.client import AgentLink, LinkError
from a2alink.registry import Registry, make_server


def free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def boot(local_mesh: bool):
    tmp = tempfile.mkdtemp(prefix="a2a-x-")
    port = free_port()
    reg = Registry(os.path.join(tmp, "t.sqlite3"), local_mesh=local_mesh)
    srv = make_server(reg, "127.0.0.1", port)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    time.sleep(0.12)
    return reg, srv, f"http://127.0.0.1:{port}", tmp


class TestSameMachineMesh(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.reg, cls.srv, cls.url, cls.tmp = boot(local_mesh=True)

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()
        cls.srv.server_close()   # shutdown 不关监听 socket
        cls.reg.close()          # 不关就靠 GC，测试跑多了会攒出 fd 泄漏

    def sess(self, name: str) -> AgentLink:
        """模拟"一个对话窗口"：独立 home、独立密钥、独立身份。"""
        home = os.path.join(self.tmp, f"sess-{name}")
        os.environ["A2ALINK_QUIET"] = "1"
        return AgentLink(registry=self.url, name=f"s-{name}", home=home)

    def test_send_without_friendship(self):
        a, b = self.sess("ops"), self.sess("writer")
        s = a.send_text(b.agent_id, "502 已修复，请回归验证", act="event")
        self.assertTrue(s.env.id)
        got = b.recv(wait=3)
        self.assertEqual(len(got), 1)
        self.assertTrue(got[0].authenticated, "同机互发也必须验签通过")
        self.assertIn("502", got[0].text)

    def test_ask_reply_roundtrip(self):
        a, b = self.sess("a1"), self.sess("b1")
        s = a.send(b.agent_id, {"instruction": "retry 字段叫什么",
                                "need_reply": True}, act="task")
        q = b.recv(wait=3)
        self.assertEqual(len(q), 1)
        self.assertTrue(q[0].env.in_reply_to is None)

        # 回答必须带 in_reply_to，且 stage=done —— 一条链走完就结束
        r = b.send(a.agent_id, {"instruction": "叫 retry_count"},
                   act="result", stage="done",
                   conversation_id=q[0].env.conversation_id,
                   in_reply_to=q[0].env.id)
        ans = a.recv(wait=3)
        self.assertEqual(len(ans), 1)
        self.assertEqual(ans[0].env.in_reply_to, q[0].env.id)
        self.assertEqual(ans[0].env.stage, "done")
        self.assertEqual(ans[0].env.conversation_id, s.env.conversation_id)
        self.assertIn("retry_count", ans[0].text)
        self.assertEqual(r.env.id, ans[0].env.id)

    def test_mesh_pass_is_audited(self):
        a, b = self.sess("a2"), self.sess("b2")
        a.send_text(b.agent_id, "ping", act="event")
        rows = [x for x in self.reg.audit_log(500)
                if x.get("reason") == "mesh.local_trust"]
        self.assertTrue(rows, "同机放行没有留审计记录——事后就说不清它凭什么发出去")
        self.assertEqual(rows[0]["decision"], "note")

    def test_identity_is_stable_across_calls(self):
        """同一个对话被调用多次，必须是同一个人。

        这一条要是破了，每跑一次 CLI 就多一个 agent，消息投出去没人收。
        """
        home = os.path.join(self.tmp, "sess-stable")
        os.environ["A2ALINK_QUIET"] = "1"
        x = AgentLink(registry=self.url, name="s-stable", home=home)
        y = AgentLink(registry=self.url, name="s-stable", home=home)
        self.assertEqual(x.agent_id, y.agent_id)
        self.assertEqual(x.keys.signing.public_b64, y.keys.signing.public_b64)


class TestNoMesh(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.reg, cls.srv, cls.url, cls.tmp = boot(local_mesh=False)

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()
        cls.srv.server_close()   # shutdown 不关监听 socket
        cls.reg.close()          # 不关就靠 GC，测试跑多了会攒出 fd 泄漏

    def test_strangers_blocked(self):
        os.environ["A2ALINK_QUIET"] = "1"
        a = AgentLink(registry=self.url, name="s-x",
                      home=os.path.join(self.tmp, "hx"))
        b = AgentLink(registry=self.url, name="s-y",
                      home=os.path.join(self.tmp, "hy"))
        with self.assertRaises(LinkError) as cm:
            a.send_text(b.agent_id, "hi", act="event")
        self.assertEqual(cm.exception.code, "not_friends")

    def test_friends_still_work(self):
        os.environ["A2ALINK_QUIET"] = "1"
        a = AgentLink(registry=self.url, name="s-p",
                      home=os.path.join(self.tmp, "hp"))
        b = AgentLink(registry=self.url, name="s-q",
                      home=os.path.join(self.tmp, "hq"))
        a.friend_request(b.name)
        b.friend_accept(b.pending_requests()[0]["id"])
        a.send_text(b.agent_id, "现在可以了", act="event")
        self.assertEqual(len(b.recv(wait=3)), 1)


class TestSessionIdentities(unittest.TestCase):
    """把 sessions.py 和 AgentLink 接起来看：不同会话 → 不同身份 → 能互通。"""

    def test_two_sessions_are_different_agents(self):
        root = tempfile.mkdtemp(prefix="a2a-sid-")
        st = sessions.SessionStore(root)
        one = sessions.current(st, env={"CODEBUDDY_SESSION_ID": "sess-one-1111"})
        two = sessions.current(st, env={"CODEBUDDY_SESSION_ID": "sess-two-2222"})
        self.assertNotEqual(one.agent_name, two.agent_name)
        self.assertNotEqual(one.home, two.home)
        self.assertNotEqual(one.sid, two.sid)

    def test_same_session_reuses_identity(self):
        root = tempfile.mkdtemp(prefix="a2a-sid-")
        st = sessions.SessionStore(root)
        env = {"CODEBUDDY_SESSION_ID": "sess-fixed-9999"}
        a = sessions.current(st, env=env)
        b = sessions.current(st, env=env)
        self.assertEqual(a.agent_name, b.agent_name)
        self.assertEqual(a.home, b.home)


class TestAutostartHelpers(unittest.TestCase):
    def test_split_local(self):
        for url in ("http://127.0.0.1:8787", "http://localhost:9000"):
            host, port, local = autostart.split_registry(url)
            self.assertTrue(local, url)

    def test_split_remote(self):
        for url in ("https://a2a.example.com", "http://10.0.0.5:8787"):
            host, port, local = autostart.split_registry(url)
            self.assertFalse(local, url)

    def test_probe_dead_port(self):
        self.assertIsNone(autostart.probe(f"http://127.0.0.1:{free_port()}"))

    def test_probe_recognises_a2alink(self):
        reg, srv, url, tmp = boot(local_mesh=True)
        try:
            self.assertIsNotNone(autostart.probe(url))
        finally:
            srv.shutdown()
            srv.server_close()
            reg.close()

    def test_ensure_does_not_touch_remote(self):
        out = autostart.ensure("https://not-exist.invalid")
        self.assertFalse(out["managed"])
        self.assertFalse(out["alive"])


if __name__ == "__main__":
    unittest.main()
