"""协议层测试：信封校验、TTL 递减、预算继承。"""

import os
import sys
import time
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from a2alink.protocol import (ACT_TASK, Budget, Envelope, ProtocolError,
                              STAGE_DONE, estimate_tokens, make_task)


class TestEnvelope(unittest.TestCase):
    def test_roundtrip(self):
        env = make_task("agt-a", "agt-b", "查一下 502 的根因")
        d = env.to_dict()
        env2 = Envelope.from_dict(d)
        self.assertEqual(env.id, env2.id)
        self.assertEqual(env.conversation_id, env2.conversation_id)
        self.assertEqual(env.fingerprint(), env2.fingerprint())

    def test_reject_bad_act(self):
        d = make_task("agt-a", "agt-b", "x").to_dict()
        d["act"] = "shutdown"
        with self.assertRaises(ProtocolError):
            Envelope.from_dict(d)

    def test_reject_ttl_over_hard_limit(self):
        d = make_task("agt-a", "agt-b", "x").to_dict()
        d["ttl_hops"] = 999
        with self.assertRaises(ProtocolError):
            Envelope.from_dict(d)

    def test_reject_expired_order(self):
        d = make_task("agt-a", "agt-b", "x").to_dict()
        d["expires_at"] = d["created_at"] - 1
        with self.assertRaises(ProtocolError):
            Envelope.from_dict(d)

    def test_reject_oversize(self):
        d = make_task("agt-a", "agt-b", "x").to_dict()
        d["payload"] = {"instruction": "a" * (70 * 1024)}
        with self.assertRaises(ProtocolError):
            Envelope.from_dict(d)

    def test_reply_decrements_ttl_and_budget(self):
        env = make_task("agt-a", "agt-b", "干活", ttl_hops=3, max_messages=5)
        r = env.reply("agt-b", {"status": "ok"})
        self.assertEqual(r.ttl_hops, 2)
        self.assertEqual(r.to_id, "agt-a")
        self.assertEqual(r.conversation_id, env.conversation_id)
        self.assertEqual(r.in_reply_to, env.id)
        self.assertEqual(r.budget.used_messages, 1)
        self.assertEqual(r.stage, STAGE_DONE)

    def test_budget_exhausted(self):
        b = Budget(max_messages=2, max_tokens=100, used_messages=2)
        self.assertTrue(b.exhausted())
        b2 = Budget(max_messages=2, max_tokens=100, used_messages=1)
        self.assertFalse(b2.exhausted())

    def test_estimate_tokens_cjk(self):
        self.assertEqual(estimate_tokens("中文十一个字"), 6)   # 6 个汉字 ≈ 6 token
        self.assertGreaterEqual(estimate_tokens("中文十一个字"), 6)
        self.assertLessEqual(estimate_tokens("hello world"), 4)

    def test_expired_flag(self):
        env = make_task("agt-a", "agt-b", "x", ttl_seconds=1)
        self.assertFalse(env.expired())
        self.assertTrue(env.expired(time.time() + 5))


if __name__ == "__main__":
    unittest.main()
