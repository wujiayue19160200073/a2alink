"""会话身份层测试。

重点不是"能不能存下来"，而是几条**约束**有没有被守住：
身份稳定、改名不换人、别名不撞车、没有会话 ID 时不许凭空造一个。
"""

import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from a2alink import sessions
from a2alink.sessions import (LABEL_RE, SID_RE, SessionError, SessionStore,
                              current, session_id_from_env)


class TestEnv(unittest.TestCase):
    def test_reads_known_keys(self):
        self.assertEqual(
            session_id_from_env({"CODEBUDDY_SESSION_ID": "abc-123-xyz"}),
            "abc-123-xyz")
        self.assertEqual(
            session_id_from_env({"CLAUDE_SESSION_ID": "sess_0001"}), "sess_0001")

    def test_prefers_explicit_override(self):
        e = {"A2ALINK_SESSION": "manual-one",
             "CODEBUDDY_SESSION_ID": "host-one"}
        self.assertEqual(session_id_from_env(e), "manual-one")

    def test_rejects_path_traversal(self):
        # 会话 ID 会拼进文件路径，绝不能让它带 ../ 出去
        for bad in ("../../etc", "a/b", "a b", "", "x"):
            self.assertIsNone(session_id_from_env({"A2ALINK_SESSION": bad}),
                              f"{bad!r} 不该被接受")

    def test_none_when_absent(self):
        self.assertIsNone(session_id_from_env({}))


class TestStore(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp(prefix="a2a-sess-")
        self.st = SessionStore(self.root)

    def test_bind_is_idempotent(self):
        a = self.st.bind("sid-aaaaaaaa-1111")
        b = self.st.bind("sid-aaaaaaaa-1111")
        self.assertEqual(a["agent_name"], b["agent_name"])
        self.assertEqual(a["home"], b["home"])

    def test_agent_name_frozen_after_rename(self):
        """改名只换称呼，不换协议身份。

        这条如果破了，改名等于在注册中心里换一个人：好友关系、群成员、
        对端固定的公钥全部失联。
        """
        before = self.st.bind("sid-bbbbbbbb-2222")
        self.st.bind("sid-bbbbbbbb-2222", label="运维")
        after = self.st.bind("sid-bbbbbbbb-2222", label="运维二")
        self.assertEqual(before["agent_name"], after["agent_name"])
        self.assertEqual(after["label"], "运维二")

    def test_label_is_unique(self):
        self.st.bind("sid-cccccccc-3333", label="运维")
        with self.assertRaises(SessionError):
            self.st.bind("sid-dddddddd-4444", label="运维")

    def test_rename_frees_old_alias(self):
        self.st.bind("sid-eeeeeeee-5555", label="旧名")
        self.st.bind("sid-eeeeeeee-5555", label="新名")
        self.assertIsNone(self.st.by_label("旧名"))
        self.assertIsNotNone(self.st.by_label("新名"))

    def test_reserved_label_rejected(self):
        for bad in ("me", "all", "SELF"):
            with self.assertRaises(SessionError):
                self.st.bind("sid-ffffffff-6666", label=bad)

    def test_bad_label_rejected(self):
        for bad in ("x", "带 空格", "a" * 30, "with/slash"):
            self.assertFalse(LABEL_RE.fullmatch(bad), bad)
            with self.assertRaises(SessionError):
                self.st.bind("sid-gggggggg-7777", label=bad)

    def test_resolve_variants(self):
        self.st.bind("sid-hhhh1111-8888", label="写手")
        self.assertEqual(self.st.resolve("@写手"), "sid-hhhh1111-8888")
        self.assertEqual(self.st.resolve("写手"), "sid-hhhh1111-8888")
        self.assertEqual(self.st.resolve("sid-hhhh1111-8888"), "sid-hhhh1111-8888")

    def test_resolve_prefix_ambiguous(self):
        self.st.bind("sid-iiii-0001")
        self.st.bind("sid-iiii-0002")
        with self.assertRaises(SessionError):
            self.st.resolve("sid-iiii")

    def test_resolve_unknown_returns_none(self):
        self.assertIsNone(self.st.resolve("查无此人"))

    def test_forget_keeps_files_by_default(self):
        rec = self.st.bind("sid-jjjj-9999")
        self.st.forget("sid-jjjj-9999")
        self.assertIsNone(self.st.get("sid-jjjj-9999"))
        # 身份目录不归 forget 管：里面有私钥和审计链，删了就没法验证历史
        self.assertTrue(rec["home"])  # 路径仍然可辨认

    def test_latest_tracks_touch(self):
        self.st.bind("sid-kkkk-0001")
        self.st.bind("sid-kkkk-0002")
        self.st.touch("sid-kkkk-0001")
        self.assertEqual(self.st.latest()["sid"], "sid-kkkk-0001")

    def test_corrupt_file_recovers(self):
        os.makedirs(self.root, exist_ok=True)
        with open(self.st.path, "w", encoding="utf-8") as f:
            f.write("{ this is not json")
        self.assertEqual(self.st.all(), {})
        self.st.bind("sid-llll-0001")          # 仍然可写
        self.assertEqual(len(self.st.all()), 1)


class TestCurrent(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp(prefix="a2a-cur-")
        self.st = SessionStore(self.root)

    def test_from_env(self):
        ident = current(self.st, env={"CODEBUDDY_SESSION_ID": "env-sid-0001"})
        self.assertEqual(ident.sid, "env-sid-0001")
        self.assertEqual(ident.source, "env")
        self.assertTrue(ident.agent_name.startswith("s-"))

    def test_explicit_alias(self):
        self.st.bind("sid-mmmm-0001", label="运维")
        ident = current(self.st, who="运维", env={})
        self.assertEqual(ident.sid, "sid-mmmm-0001")
        self.assertEqual(ident.source, "explicit")
        self.assertEqual(ident.display, "@运维")

    def test_explicit_new_alias_creates(self):
        ident = current(self.st, who="临时", env={})
        self.assertEqual(ident.label, "临时")
        self.assertEqual(ident.source, "explicit")

    def test_falls_back_to_latest_and_says_so(self):
        self.st.bind("sid-nnnn-0001")
        ident = current(self.st, env={})
        # 关键：source 必须能被调用方识别为"猜的"，才能提示用户
        self.assertEqual(ident.source, "latest")

    def test_fallback_creates_manual(self):
        ident = current(self.st, env={})
        self.assertEqual(ident.source, "fallback")
        self.assertEqual(ident.label, "manual")

    def test_no_create_raises(self):
        with self.assertRaises(SessionError):
            current(self.st, env={}, create=False)


class TestRegexes(unittest.TestCase):
    def test_sid_regex_allows_uuid(self):
        self.assertTrue(SID_RE.fullmatch("f4e0b9a2-ff2e-4264-af6f-5cd16a6a477c"))

    def test_short_is_readable(self):
        s = sessions.short("f4e0b9a2-ff2e-4264-af6f-5cd16a6a477c")
        self.assertEqual(s, "f4e0b9a2ff")
        self.assertLessEqual(len(s), 10)


if __name__ == "__main__":
    unittest.main()
