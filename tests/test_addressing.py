"""寻址层测试：一个 Agent 有多个对话时，怎么确定发给哪个。

这组测试守的是三条规则：
1. 别名是唯一的，标签是可共享的——两者语义不同，不能混用一套匹配；
2. 标签命中多个时必须报歧义，不能"挑一个最近的"——发错人的代价是
   两边都以为自己没错；
3. 优先级固定：完整 ID > 别名 > 标签 > ID 前缀。
"""

import os
import tempfile
import unittest

from a2alink import sessions
from a2alink.sessions import (MAX_TAGS, SessionError, SessionStore,
                              normalize_tags)


class TestNormalizeTags(unittest.TestCase):
    def test_splits_on_commas_and_spaces(self):
        self.assertEqual(normalize_tags("值班,数据库 应急"),
                         ["值班", "数据库", "应急"])
        self.assertEqual(normalize_tags(["值班", "数据库,应急"]),
                         ["值班", "数据库", "应急"])

    def test_dedupes_case_insensitively_but_keeps_first_spelling(self):
        self.assertEqual(normalize_tags("Ops,ops,OPS"), ["Ops"])

    def test_empty_inputs(self):
        self.assertEqual(normalize_tags(None), [])
        self.assertEqual(normalize_tags(""), [])
        self.assertEqual(normalize_tags(["", "  "]), [])

    def test_rejects_illegal_chars(self):
        with self.assertRaises(SessionError):
            normalize_tags("a@b")
        with self.assertRaises(SessionError):
            normalize_tags("a/b")

    def test_rejects_too_long_tag(self):
        with self.assertRaises(SessionError):
            normalize_tags("x" * 17)

    def test_rejects_too_many_tags(self):
        with self.assertRaises(SessionError):
            normalize_tags([f"t{i}" for i in range(MAX_TAGS + 1)])

    def test_strips_leading_hash(self):
        self.assertEqual(normalize_tags("#值班"), ["值班"])


class TestTagAddressing(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp(prefix="a2a-addr-")
        self.st = SessionStore(self.root)
        self.st.bind("sess-ops-01", label="运维", tags="值班,数据库")
        self.st.bind("sess-wri-02", label="写手", tags="值班,文档")
        self.st.bind("sess-tst-03", label="测试", tags="测试")

    # ---------------- 唯一匹配 ----------------
    def test_unique_tag_resolves(self):
        self.assertEqual(self.st.resolve("数据库"), "sess-ops-01")
        self.assertEqual(self.st.resolve("测试"), "sess-tst-03")

    def test_tag_with_at_prefix_works(self):
        self.assertEqual(self.st.resolve("@数据库"), "sess-ops-01")

    # ---------------- 歧义 ----------------
    def test_shared_tag_raises_with_candidates(self):
        with self.assertRaises(SessionError) as ctx:
            self.st.resolve("值班")
        msg = str(ctx.exception)
        self.assertIn("2 个会话", msg)
        # 必须列出候选，否则人没法决定该改成什么
        self.assertIn("@运维", msg)
        self.assertIn("@写手", msg)

    def test_ambiguity_never_picks_silently(self):
        """同一组数据反复解析，结果必须是"一直报错"，不能某次突然成功。"""
        for _ in range(5):
            with self.assertRaises(SessionError):
                self.st.resolve("值班")

    # ---------------- 优先级 ----------------
    def test_alias_beats_tag(self):
        # 让"文档"既是写手的标签，又是测试的别名
        self.st.bind("sess-tst-03", label="文档")
        self.assertEqual(self.st.resolve("文档"), "sess-tst-03",
                         "别名是明确的名字，应该赢过标签")

    def test_full_sid_beats_everything(self):
        self.assertEqual(self.st.resolve("sess-ops-01"), "sess-ops-01")

    def test_prefix_still_works_when_unique(self):
        self.assertEqual(self.st.resolve("sess-wri"), "sess-wri-02")

    def test_prefix_ambiguity_raises(self):
        with self.assertRaises(SessionError):
            self.st.resolve("sess-")      # 三个都以 sess- 开头

    def test_unknown_returns_none(self):
        self.assertIsNone(self.st.resolve("查无此人"))

    # ---------------- 标签生命周期 ----------------
    def test_set_tags_replaces(self):
        rec = self.st.set_tags("sess-ops-01", ["夜间"])
        self.assertEqual(rec["tags"], ["夜间"])
        self.assertIsNone(self.st.resolve("数据库"))
        self.assertEqual(self.st.resolve("夜间"), "sess-ops-01")

    def test_clear_tags(self):
        self.st.set_tags("sess-ops-01", [])
        self.assertEqual(self.st.find_by_tag("数据库"), [],
                         "清空后它独占的标签应该找不到人")
        # 「值班」还有写手在用，所以不该一起变空——标签是共享属性，
        # 清一个人的不影响别人。这条断言在守这个语义。
        self.assertEqual([r["label"] for r in self.st.find_by_tag("值班")], ["写手"])

    def test_find_by_tag_sorted_by_recency(self):
        import time
        # 让 ops 更新一次，应该排前面
        time.sleep(0.01)
        self.st.touch("sess-ops-01")
        rows = self.st.find_by_tag("值班")
        self.assertEqual([r["label"] for r in rows][0], "运维")

    def test_set_tags_on_missing_session_raises(self):
        with self.assertRaises(SessionError):
            self.st.set_tags("nope-nope", ["x"])

    def test_bind_without_tags_keeps_existing(self):
        self.st.bind("sess-ops-01", label="运维")
        rec = self.st.get("sess-ops-01")
        self.assertEqual(rec["tags"], ["值班", "数据库"],
                         "不传 tags 表示别动，不是清空")

    def test_bind_tags_survive_rename(self):
        self.st.bind("sess-ops-01", label="值班长")
        rec = self.st.get("sess-ops-01")
        self.assertEqual(rec["label"], "值班长")
        self.assertEqual(rec["tags"], ["值班", "数据库"])

    # ---------------- 旧数据兼容 ----------------
    def test_old_records_without_tags_still_work(self):
        import json
        p = os.path.join(self.root, "sessions.json")
        with open(p, encoding="utf-8") as f:
            d = json.load(f)
        for r in d["sessions"].values():
            r.pop("tags", None)          # 模拟 v0.2 时代写下的记录
        with open(p, "w", encoding="utf-8") as f:
            json.dump(d, f, ensure_ascii=False)
        st = SessionStore(self.root)
        self.assertEqual(st.resolve("运维"), "sess-ops-01")
        self.assertEqual(st.find_by_tag("值班"), [])
        st.set_tags("sess-ops-01", ["值班"])
        self.assertEqual(st.resolve("值班"), "sess-ops-01")


class TestIdentityExposesTags(unittest.TestCase):
    def test_identity_to_dict_includes_tags(self):
        root = tempfile.mkdtemp(prefix="a2a-addr2-")
        st = SessionStore(root)
        ident = sessions.current(st, who="值班组")
        st.set_tags(ident.sid, ["值班"])
        ident = sessions.current(st, who="值班组")
        self.assertEqual(ident.tags, ["值班"])
        self.assertEqual(ident.to_dict()["tags"], ["值班"])


if __name__ == "__main__":
    unittest.main()
