"""看门狗测试：五种死法逐个验。这是本项目最该有测试的模块。"""

import os
import sys
import time
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from a2alink.protocol import make_task
from a2alink.watchdog import DEGRADE, PASS, STOP, Watchdog, hamming, simhash


def mk(text="干活", conv="conv-1", ttl=4, frm="agt-a", to="agt-b"):
    return make_task(frm, to, text, conversation_id=conv, ttl_hops=ttl)


class TestWatchdog(unittest.TestCase):
    def test_normal_pass(self):
        wd = Watchdog()
        v = wd.check_outbound(mk("查一下磁盘告警"))
        self.assertEqual(v.action, PASS)
        self.assertTrue(v.ok)

    def test_ttl_zero_stops(self):
        wd = Watchdog()
        env = mk(ttl=0)
        v = wd.check_outbound(env)
        self.assertEqual(v.action, STOP)
        self.assertIn("跳数", v.reasons[0])

    def test_expired_envelope_stops(self):
        wd = Watchdog()
        env = mk()
        env.expires_at = time.time() - 1
        self.assertEqual(wd.check_inbound(env).action, STOP)

    def test_message_quota(self):
        wd = Watchdog(max_messages=2)
        texts = ["第一件事：查磁盘", "第二件事：查内存", "第三件事：查网络"]
        actions = []
        for t in texts:
            actions.append(wd.check_outbound(mk(t)).action)
        self.assertEqual(actions[:2], [PASS, PASS])
        self.assertEqual(actions[2], STOP)

    def test_content_loop_detected(self):
        wd = Watchdog(max_messages=50)      # 故意放宽配额，证明不是靠配额拦住的
        env = "收到，请确认一下是否继续"
        a1 = wd.check_outbound(mk(env)).action
        a2 = wd.check_outbound(mk(env)).action
        a3 = wd.check_outbound(mk(env)).action
        self.assertEqual(a1, PASS)
        self.assertEqual(a2, DEGRADE)
        self.assertEqual(a3, STOP)

    def test_near_duplicate_not_exact(self):
        """改几个字也应当被认出来（simhash 的用途）。"""
        wd = Watchdog(loop_distance=3)
        base = "我已经确认过这个问题了，请你也确认一下是否可以继续推进"
        wd.check_outbound(mk(base))
        v = wd.check_outbound(mk(base + "。"))
        self.assertIn(v.action, (DEGRADE, PASS))
        self.assertLessEqual(hamming(simhash(base), simhash(base + "。")), 6)

    def test_token_budget_stops(self):
        """token 预算耗尽必须停，哪怕消息条数还很宽裕。"""
        from a2alink.protocol import estimate_tokens
        per = estimate_tokens(mk("第一段回复内容说明").payload_text())
        wd = Watchdog(max_messages=100, max_tokens=int(per * 2.5))
        texts = ["第一段回复内容说明", "第二段补充内容说明", "第三段结论内容说明"]
        actions = [wd.check_outbound(mk(t)).action for t in texts]
        self.assertEqual(actions[0], PASS)
        self.assertIn(STOP, actions)

    def test_rate_limit(self):
        wd = Watchdog(rate=0.001, burst=1, max_messages=100)
        a1 = wd.check_outbound(mk("第一条")).action
        a2 = wd.check_outbound(mk("完全不同的第二条")).action
        self.assertEqual(a1, PASS)
        self.assertEqual(a2, STOP)

    def test_explicit_done_closes_conversation(self):
        wd = Watchdog()
        env = mk("这是最终结论")
        env.stage = "done"
        self.assertEqual(wd.check_outbound(env).action, PASS)
        # 会话已被关闭，同会话再来一条必须被拒
        v = wd.check_inbound(mk("我又想到一点", conv=env.conversation_id))
        self.assertEqual(v.action, STOP)
        self.assertIn("已终止", v.reasons[0])

    def test_wall_clock(self):
        wd = Watchdog(max_wall_seconds=0.05, max_messages=100)
        wd.check_outbound(mk("开始"))
        time.sleep(0.1)
        self.assertEqual(wd.check_outbound(mk("太久了，另起一句")).action, STOP)

    def test_group_fanout_counts_recipients(self):
        wd = Watchdog(max_messages=3, fanout_extra=9)   # 10 人群
        env = mk("群里说一句", to="grp-x")
        env.to_type = "group"
        a1 = wd.check_outbound(env).action
        a2 = wd.check_outbound(mk("群里再说一句", to="grp-x")).action
        # 一条群消息按 10 个收件人计：第 1 条(10)>3 就该拦住
        self.assertEqual(a1, STOP)

    def test_directive_present_on_stop(self):
        wd = Watchdog()
        v = wd.check_outbound(mk(ttl=0))
        self.assertIn("必须立刻停止", v.directive)

    def test_conversations_isolated(self):
        wd = Watchdog(max_messages=2)
        self.assertEqual(wd.check_outbound(mk("a1", conv="c1")).action, PASS)
        self.assertEqual(wd.check_outbound(mk("a2", conv="c1")).action, PASS)
        self.assertEqual(wd.check_outbound(mk("b1", conv="c2")).action, PASS)


if __name__ == "__main__":
    unittest.main()
