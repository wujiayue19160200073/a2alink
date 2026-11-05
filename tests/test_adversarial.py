"""对抗性回归用例：不问"正常输入对不对"，只问"怎么让防线失效"。

这一组用例的来历：199 个常规用例全绿的同时，出站护栏能被 200 个假 IP
压掉后面的身份证规则。原因是那时的测试只覆盖"正常流程 + 明显非法输入"，
没有一条去攻击"上限""重叠""非标准字面量"这些边角。

固定动作：**每加一条安全规则，同时加一条"如何让这条规则不生效"的用例。**
"""

import os
import sys
import time
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from a2alink.guard import (ALLOW, BLOCK, REDACT, SCOPE_LAN, SCOPE_WAN,
                           EgressGuard, Finding)
from a2alink.protocol import Envelope, ProtocolError


def _envelope(**over) -> dict:
    raw = {
        "v": "1", "id": "m1", "from": "attacker",
        "to": {"type": "agent", "id": "victim"},
        "act": "task", "stage": "open", "conversation_id": "c1",
        "payload": {"instruction": "hi"},
        "created_at": 1.0, "expires_at": 2.0, "ttl_hops": 4,
    }
    raw.update(over)
    return raw


class GuardFloodTests(unittest.TestCase):
    """规则数量压制：用大量低价值命中把后面的规则挤掉。"""

    def test_id_card_survives_ip_flood(self):
        g = EgressGuard(scope=SCOPE_WAN)
        payload = ("10.1.1.1 " * 200) + " 身份证 110101199003071234 手机 13800138000"
        r = g.check(payload)
        rules = {f.rule for f in r.findings}
        self.assertTrue(
            rules & {"cn_id_card", "cn_phone"},
            f"身份证/手机号规则被前面的 IP 命中挤掉了：{sorted(rules)}")

    def test_id_card_survives_larger_flood(self):
        """上限之上再加量，仍然不能把高severity规则挤出去。"""
        g = EgressGuard(scope=SCOPE_WAN)
        payload = ("10.2.3.4 " * 2000) + " 110101199003071234"
        r = g.check(payload)
        self.assertIn("cn_id_card", {f.rule for f in r.findings})

    def test_each_rule_has_its_own_quota(self):
        """单条规则不能占满全局名额：一条规则刷屏时，其它规则仍要有位置。"""
        g = EgressGuard(scope=SCOPE_WAN)
        payload = ("10.9.9.9 " * 500) + " a@b.com 110101199003071234"
        found = {f.rule for f in g.check(payload).findings}
        self.assertIn("cn_id_card", found)
        self.assertIn("email", found)

    def test_findings_capped(self):
        """有上限，但不能因为上限把文本撑爆（DoS 面）。"""
        g = EgressGuard(scope=SCOPE_WAN)
        r = g.check("10.1.1.1 " * 5000)
        self.assertLessEqual(len(r.findings), 1000)


class RedactOverlapTests(unittest.TestCase):
    """脱敏时区间重叠会导致偏移错位、丢字符。"""

    def test_overlapping_ranges_drop_nothing(self):
        g = EgressGuard(scope=SCOPE_LAN)
        text = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        f1 = Finding(rule="a", severity="medium", category="x", excerpt="",
                     start=2, end=15, replacement="[X]")
        f2 = Finding(rule="b", severity="medium", category="x", excerpt="",
                     start=8, end=20, replacement="[Y]")
        out = g._redact(text, [f1, f2])
        # 合并后区间是 [2,20)：前缀 "AB" + 一个占位 + 后缀 "UVWXYZ"
        self.assertTrue(out.startswith("AB["), out)
        self.assertTrue(out.endswith("UVWXYZ"), out)
        self.assertEqual(len(out), 2 + 3 + 6, out)

    def test_adjacent_ranges_kept_separate(self):
        """首尾相接但**不重叠**的两段是两处敏感信息，各换各的，不能丢字符。"""
        g = EgressGuard(scope=SCOPE_LAN)
        f1 = Finding("a", "medium", "x", "", start=0, end=3, replacement="[A]")
        f2 = Finding("b", "medium", "x", "", start=3, end=6, replacement="[B]")
        out = g._redact("123456789", [f1, f2])
        self.assertEqual(out, "[A][B]789")

    def test_identical_ranges_not_double_replaced(self):
        g = EgressGuard(scope=SCOPE_LAN)
        f1 = Finding("a", "medium", "x", "", start=1, end=4, replacement="[A]")
        f2 = Finding("b", "medium", "x", "", start=1, end=4, replacement="[B]")
        out = g._redact("0123456", [f1, f2])
        self.assertEqual(out, "0[A]456")

    def test_real_conn_string_keeps_readable(self):
        g = EgressGuard(scope=SCOPE_WAN)
        text = "连接串 mysql://root:pass123@10.20.30.40:3306/db 邮箱 a@b.com"
        r = g.check(text)
        self.assertIn(r.action, (REDACT, BLOCK))
        if r.action == REDACT:
            self.assertEqual(r.text[:3], "连接串", r.text)


class ProtocolLiteralTests(unittest.TestCase):
    """非标准 JSON 字面量与类型混淆。"""

    def test_infinity_expires_rejected(self):
        with self.assertRaises(ProtocolError):
            Envelope.from_dict(_envelope(expires_at=float("inf")))

    def test_nan_created_rejected(self):
        with self.assertRaises(ProtocolError):
            Envelope.from_dict(_envelope(created_at=float("nan")))

    def test_negative_expires_rejected(self):
        with self.assertRaises(ProtocolError):
            Envelope.from_dict(_envelope(expires_at=-1.0))

    def test_non_finite_in_raw_json(self):
        raw = ('{"v":"1","id":"m","from":"a","to":{"type":"agent","id":"b"},'
               '"act":"task","stage":"open","conversation_id":"c","payload":{},'
               '"created_at":1.0,"expires_at":Infinity,"ttl_hops":1}')
        with self.assertRaises(ProtocolError):
            Envelope.from_json(raw)

    def test_capabilities_must_be_list(self):
        with self.assertRaises(ProtocolError):
            Envelope.from_dict(_envelope(capabilities="hack"))

    def test_capabilities_items_must_be_str(self):
        with self.assertRaises(ProtocolError):
            Envelope.from_dict(_envelope(capabilities=[{"a": 1}]))

    def test_deep_nesting_is_protocol_error(self):
        deep = "[" * 3000 + "]" * 3000
        with self.assertRaises(ProtocolError):
            Envelope.from_json('{"v":"1","payload":' + deep + "}")


class DoSTests(unittest.TestCase):
    """超长输入不能让单个请求把 CPU 吃满（正则回溯 / O(n²)）。"""

    def test_long_single_line_guard_is_linear(self):
        g = EgressGuard(scope=SCOPE_WAN)
        payload = ("a1" * 100_000) + " 110101199003071234"
        t0 = time.perf_counter()
        r = g.check(payload)
        elapsed = time.perf_counter() - t0
        self.assertLess(elapsed, 5.0, f"20 万字符耗时 {elapsed:.2f}s，疑似 O(n²)")
        self.assertIn("cn_id_card", {f.rule for f in r.findings})

    def test_many_lines_guard_is_fast(self):
        g = EgressGuard(scope=SCOPE_WAN)
        payload = "abc\n" * 50_000
        t0 = time.perf_counter()
        g.check(payload)
        self.assertLess(time.perf_counter() - t0, 5.0)


class AllowPathTests(unittest.TestCase):
    """堵完洞之后，正常内容必须还能正常走 —— 否则护栏会被用户关掉。"""

    def test_normal_text_allowed(self):
        g = EgressGuard(scope=SCOPE_WAN)
        r = g.check("明天下午三点对一下接口联调，文档在 docs/api.md")
        self.assertEqual(r.action, ALLOW, r.reasons)

    def test_public_url_allowed(self):
        g = EgressGuard(scope=SCOPE_WAN)
        r = g.check("参考 https://example.com/docs?id=3 这一页")
        self.assertIn(r.action, (ALLOW, REDACT), r.reasons)


if __name__ == "__main__":
    unittest.main(verbosity=2)
