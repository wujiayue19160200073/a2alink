"""审计链的测试。

这里每个用例都对应一次真实踩过的坑，不是凑覆盖率：
· 日志自身不能留明文（否则"防泄密的工具"变成新的泄密源）
· 改一条 / 删中间 / 删尾部都要检得出来（否则日志不能当证据）
· 重启要接续（否则"重启大法"能洗掉历史）
· 归档后链要继续（否则归档动作本身会把证据验成"被破坏"）
· force 必须带理由（否则"强行放行"成了没有成本的默认操作）
"""

import json
import os
import shutil
import tempfile
import unittest

from a2alink.audit import (AuditError, AuditLog, OVERRIDE_REASONS, REASONS,
                           _digest, mask, scrub)


def _read(path: str, mode: str = "r"):
    """测试里读文件统一走这里。裸 open().read() 会漏文件句柄，
    跑多了就是满屏 ResourceWarning，把真正的告警淹掉。"""
    if "b" in mode:
        with open(path, mode) as fh:
            return fh.read()
    with open(path, mode, encoding="utf-8") as fh:
        return fh.read()


def _write(path: str, text: str) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(text)


class TestScrub(unittest.TestCase):
    def test_credentials_removed(self):
        s = scrub("AK 是 AKIAIOSFODNN7EXAMPLE，密码 password=hunter2，"
                  "私钥 -----BEGIN RSA PRIVATE KEY----- MIIE -----END RSA PRIVATE KEY-----")
        self.assertNotIn("AKIAIOSFODNN7EXAMPLE", s)
        self.assertNotIn("hunter2", s)
        self.assertNotIn("MIIE", s)

    def test_ip_and_pii_removed(self):
        s = scrub("服务器 10.20.31.7，电话 13812345678，"
                  "身份证 110101199003077777，邮箱 ops@corp.internal")
        for bad in ("10.20.31.7", "13812345678", "110101199003077777", "ops@corp.internal"):
            self.assertNotIn(bad, s)

    def test_scrub_before_truncate(self):
        """先截断再脱敏会切断密钥导致漏检，顺序不能反。"""
        s = scrub("x" * 60 + " sk-abcdefghijklmnopqrstuvwxyz", limit=30)
        self.assertNotIn("sk-abcdefghijklmnopqrstuvwxyz", s)

    def test_mask_keeps_edges(self):
        self.assertEqual(mask("agt-1234567890"), "ag**********90")
        self.assertEqual(mask("ab"), "**")


class TestChain(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp()
        self.log = AuditLog(self.root, "agent:agt-test")

    def tearDown(self):
        self.log.close()
        shutil.rmtree(self.root, ignore_errors=True)

    def _path(self):
        return self.log._path

    def test_clean_chain_verifies(self):
        for i in range(5):
            self.log.write("gate.egress", "allow", "egress.allow", trace=f"t{i}")
        rep = self.log.verify()
        self.assertTrue(rep["ok"], rep["errors"])
        self.assertEqual(rep["records"], 5)

    def test_no_plaintext_in_file(self):
        """最关键的约束：日记不能是第二份敏感数据副本。"""
        self.log.write("gate.egress", "deny", "egress.deny", trace="t1",
                       detail={"peer": "agt-x"},
                       preview="服务器 10.20.31.7 上 AKIAIOSFODNN7EXAMPLE 报错")
        raw = _read(self._path())
        self.assertNotIn("10.20.31.7", raw)
        self.assertNotIn("AKIAIOSFODNN7EXAMPLE", raw)
        # 但仍然要留下可排查的线索
        rec = json.loads(raw.splitlines()[0])
        self.assertIn("preview_fp", rec)
        self.assertEqual(rec["preview_len"], len("服务器 10.20.31.7 上 AKIAIOSFODNN7EXAMPLE 报错"))

    def test_ids_stay_readable(self):
        """对端是谁必须看得出来，否则日志等于没记。"""
        self.log.write("gate.egress", "allow", "egress.allow",
                       detail={"peer": "agt-a2a4bbd8e65f4694883cf746",
                               "conv": "conv-abc123def456", "n": 3})
        rec = json.loads(_read(self._path()).splitlines()[0])
        self.assertEqual(rec["detail"]["peer"], "agt-a2a4bbd8e65f4694883cf746")
        self.assertEqual(rec["detail"]["conv"], "conv-abc123def456")

    def test_force_reason_preserved(self):
        """人工放行的理由是责任链核心，不许被长度策略吃掉。"""
        why = "对方是甲方安全负责人，已电话确认可以提供测试密钥"
        self.log.write("gate.egress", "note", "egress.override",
                       detail={"peer": "agt-x", "force_reason": why})
        rec = json.loads(_read(self._path()).splitlines()[0])
        self.assertEqual(rec["detail"]["force_reason"], why)

    def test_unknown_reason_rejected(self):
        """自由文本理由必须写不进去，否则又会退化成"已处理""异常"这种废话日志。"""
        with self.assertRaises(AuditError):
            self.log.write("x", "allow", "我觉得应该没问题")

    def test_tamper_one_record_detected(self):
        for i in range(4):
            self.log.write("e", "allow", "egress.allow", trace=f"t{i}")
        p = self._path()
        lines = _read(p).splitlines()
        d = json.loads(lines[1])
        d["decision"] = "deny"
        lines[1] = json.dumps(d, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        _write(p, "\n".join(lines) + "\n")
        rep = self.log.verify()
        self.assertFalse(rep["ok"])
        self.assertIn("hash_mismatch", {e["kind"] for e in rep["errors"]})

    def test_delete_middle_detected(self):
        for i in range(5):
            self.log.write("e", "allow", "egress.allow", trace=f"t{i}")
        p = self._path()
        lines = _read(p).splitlines()
        _write(p, "\n".join([lines[0], lines[3]]) + "\n")
        kinds = {e["kind"] for e in self.log.verify()["errors"]}
        self.assertIn("seq_gap", kinds)
        self.assertIn("prev_mismatch", kinds)

    def test_truncate_tail_detected(self):
        for i in range(4):
            self.log.write("e", "allow", "egress.allow")
        p = self._path()
        lines = _read(p).splitlines()
        _write(p, "\n".join(lines[:2]) + "\n")
        kinds = {e["kind"] for e in self.log.verify()["errors"]}
        self.assertIn("tail_truncated", kinds)

    def test_deny_fsync_and_type(self):
        r = self.log.write("gate.egress", "deny", "egress.deny", trace="t")
        self.assertEqual(r["decision"], "deny")
        self.assertIn("egress.deny", REASONS)

    def test_override_reason_registered(self):
        """override 必须是登记过的理由码，否则统计口径会漂。"""
        self.assertTrue(OVERRIDE_REASONS)
        for r in OVERRIDE_REASONS:
            self.assertIn(r, REASONS)

    def test_query_by_trace(self):
        self.log.write("a", "allow", "egress.allow", trace="trace-aaa")
        self.log.write("b", "allow", "egress.allow", trace="trace-bbb")
        got = self.log.read(trace="trace-aaa")
        self.assertEqual(len(got), 1)
        self.assertEqual(got[0]["trace"], "trace-aaa")

    def test_stats(self):
        self.log.write("a", "deny", "egress.deny")
        self.log.write("b", "allow", "egress.allow")
        self.log.write("c", "note", "egress.override")
        st = self.log.stats()
        self.assertEqual(st["denied"], 1)
        self.assertEqual(st["overrides"], 1)


class TestRestartAndSeal(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.root, ignore_errors=True)

    def test_restart_continues_chain(self):
        """重启后必须接续；否则"重启一次"就能把历史切干净。"""
        a = AuditLog(self.root, "x")
        a.write("e", "allow", "egress.allow")
        a.write("e", "allow", "egress.allow")
        a.close()
        b = AuditLog(self.root, "x")
        b.write("e", "allow", "egress.allow")
        seqs = [r["seq"] for r in b.read(limit=0)]
        self.assertEqual(seqs, [1, 2, 3])
        self.assertTrue(b.verify()["ok"])
        b.close()

    def test_seal_then_continue_still_verifies(self):
        """归档不能把自己验成"证据被破坏"。"""
        a = AuditLog(self.root, "x")
        for _ in range(3):
            a.write("e", "allow", "egress.allow")
        m = a.seal("case-1")
        self.assertEqual(len(m["files"]), 1)
        self.assertTrue(os.path.exists(os.path.join(self.root, "archive", "case-1",
                                                    "MANIFEST.json")))
        b = AuditLog(self.root, "x")
        b.write("e", "allow", "egress.allow")
        rep = b.verify()
        self.assertTrue(rep["ok"], rep["errors"])
        self.assertEqual(rep["records"], 4)
        self.assertEqual([r["seq"] for r in b.read(limit=0)], [1, 2, 3, 4])
        b.close()

    def test_many_processes_single_file(self):
        """反复开关（模拟 CLI 短命进程）不应碎成多个文件。"""
        for _ in range(6):
            x = AuditLog(self.root, "x")
            x.write("e", "allow", "egress.allow")
            x.close()
        files = [n for n in os.listdir(self.root) if n.endswith(".jsonl")]
        self.assertEqual(len(files), 1, files)
        y = AuditLog(self.root, "x")
        self.assertTrue(y.verify()["ok"])
        y.close()

    def test_readonly_writes_nothing(self):
        a = AuditLog(self.root, "x")
        a.write("e", "allow", "egress.allow")
        path = a._path
        a.close()
        before = _read(path, "rb")
        ro = AuditLog(self.root, "cli", readonly=True)
        self.assertIsNone(ro.write("e", "allow", "egress.allow"))
        self.assertEqual(_read(path, "rb"), before)


if __name__ == "__main__":
    unittest.main()
