"""滥用防护测试：扩散保险丝 + 转发闸门。"""

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from a2alink.abuse import (PropagationBlocked, PropagationGuard, ProvenanceError,
                           content_fingerprint)


class TestPropagation(unittest.TestCase):
    def test_same_content_to_many_targets_blocked(self):
        g = PropagationGuard(max_targets_per_content=3)
        for i in range(3):
            g.check("同一段话", "conv-a", f"agt-{i}")     # 3 个目标，刚好到线
        with self.assertRaises(PropagationBlocked) as cm:
            g.check("同一段话", "conv-a", "agt-3")
        self.assertEqual(cm.exception.reason, "content_fanout")
        self.assertEqual(g.hits, 1)

    def test_different_content_not_blocked(self):
        g = PropagationGuard(max_targets_per_content=2)
        for i in range(10):
            g.check(f"第 {i} 段不同的话", f"conv-{i}", f"agt-{i}")
        self.assertEqual(g.hits, 0)

    def test_repeat_to_same_target_is_free(self):
        """跟同一个人聊十句不算群发——否则正常协作全被误杀。"""
        g = PropagationGuard(max_targets_per_content=2)
        for _ in range(20):
            g.check("在吗", "conv-a", "agt-x")
        self.assertEqual(g.hits, 0)

    def test_conversation_spread_blocked(self):
        """接力扩散：同一会话被带到越来越多对端，这是 handoff 链的滥用形态。"""
        g = PropagationGuard(max_targets_per_content=100, max_peers_per_conversation=3)
        for i in range(3):
            g.check(f"内容{i}", "conv-shared", f"agt-{i}")
        with self.assertRaises(PropagationBlocked) as cm:
            g.check("内容9", "conv-shared", "agt-9")
        self.assertEqual(cm.exception.reason, "conversation_spread")

    def test_forward_blocked_by_default(self):
        g = PropagationGuard()
        self.assertFalse(g.allow_forward)
        with self.assertRaises(ProvenanceError):
            g.check_forward("msg-123")

    def test_forward_allowed_when_enabled(self):
        g = PropagationGuard(allow_forward=True)
        g.check_forward("msg-123")      # 不抛

    def test_window_expiry(self):
        g = PropagationGuard(max_targets_per_content=2, window_seconds=0.01)
        g.check("同一段话", "c", "agt-1")
        g.check("同一段话", "c", "agt-2")
        import time
        time.sleep(0.03)
        g.check("同一段话", "c", "agt-3")   # 旧记录已被剪掉
        self.assertEqual(g.hits, 0)

    def test_disabled(self):
        g = PropagationGuard(max_targets_per_content=1, enabled=False)
        for i in range(50):
            g.check("刷屏", "c", f"agt-{i}")
        self.assertEqual(g.hits, 0)

    def test_fingerprint_stable(self):
        self.assertEqual(content_fingerprint("  你好 世界 "), content_fingerprint("你好 世界"))


if __name__ == "__main__":
    unittest.main()
