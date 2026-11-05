"""审批队列测试。

最关键的一条是 ``test_plaintext_never_hits_disk``：
挂起的内容本身就是"不许外发"的东西，如果它以明文躺在
~/.a2alink/approvals/ 里，这个功能就从"防泄露"变成了"多一个泄露点"。
其他测试都是在守状态机和边界条件。
"""

import json
import os
import stat
import tempfile
import time
import unittest

from a2alink.approvals import (ST_APPROVED, ST_DENIED, ST_EXPIRED, ST_PENDING,
                               ST_SENT, ApprovalError, ApprovalStore)

SECRET = "mysql://root:Tr0ub4dor@10.9.8.7:3306/prod"


def _payload(text=SECRET):
    return {"instruction": text, "intent": "note"}


class TestApprovalStore(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp(prefix="a2a-apv-")
        self.st = ApprovalStore(self.root)

    def hold(self, **kw):
        base = dict(requester="agt-me", session="s-me", peer="agt-peer",
                    scope="wan", act="task", stage="open", payload=_payload(),
                    findings=[{"rule": "conn_string"}], level="secret",
                    trace="trace-1", replay={"ttl_seconds": 3600})
        base.update(kw)
        return self.st.hold(**base)

    # ---------------------------------------------------------------- 加密
    def test_plaintext_never_hits_disk(self):
        """磁盘上任何一个字节都不该出现正文。"""
        self.hold()
        for name in os.listdir(self.st.dir):
            p = os.path.join(self.st.dir, name)
            with open(p, "rb") as f:
                blob = f.read()
            self.assertNotIn(b"Tr0ub4dor", blob, f"{name} 里有明文密码")
            self.assertNotIn("连上去".encode(), blob)
            self.assertNotIn(b"10.9.8.7", blob)

    def test_key_file_is_not_world_readable_on_posix(self):
        self.hold()
        mode = stat.S_IMODE(os.stat(self.st.key_path).st_mode)
        if os.name == "posix":
            self.assertEqual(mode, 0o600)
        else:
            # Windows 上 chmod 只影响只读位，真正的隔离靠目录 ACL。
            # 这里只确认文件存在，别假装 UAC 之外还有 Unix 式权限位。
            self.assertTrue(os.path.exists(self.st.key_path))

    def test_sealed_is_bound_to_id(self):
        """把 A 的密文挪到 B 的记录里，必须解不开（AAD 绑定 ID）。"""
        a = self.hold()
        b = self.hold()
        pa = os.path.join(self.st.dir, f"{a['id']}.json")
        pb = os.path.join(self.st.dir, f"{b['id']}.json")
        with open(pa, encoding="utf-8") as f:
            rec_a = json.load(f)
        with open(pb, encoding="utf-8") as f:
            rec_b = json.load(f)
        rec_b["sealed"] = rec_a["sealed"]          # 移花接木
        with open(pb, "w", encoding="utf-8") as f:
            json.dump(rec_b, f, ensure_ascii=False)
        with self.assertRaises(ApprovalError):
            self.st.preview(b["id"])

    def test_corrupt_key_refuses_instead_of_overwriting(self):
        """密钥损坏必须报错，不能静默重建——重建等于把已有审批件全毁掉。"""
        self.hold()
        with open(self.st.key_path, "wb") as f:
            f.write(b"short")
        with self.assertRaises(ApprovalError):
            self.st._key()
        # 文件没被覆盖
        with open(self.st.key_path, "rb") as f:
            self.assertEqual(f.read(), b"short")

    def test_missing_key_does_not_get_recreated_on_read(self):
        """只读操作不该顺手造一把新密钥。"""
        self.hold()
        os.unlink(self.st.key_path)
        self.assertEqual(self.st._key(create=False), b"")
        self.assertFalse(os.path.exists(self.st.key_path))

    # ---------------------------------------------------------------- 展示
    def test_public_view_has_no_body(self):
        rec = self.hold()
        blob = json.dumps(rec, ensure_ascii=False)
        self.assertNotIn("sealed", rec)
        self.assertNotIn("Tr0ub4dor", blob)
        self.assertEqual(rec["rules"], ["conn_string"])
        self.assertEqual(rec["status"], ST_PENDING)

    def test_list_has_no_body(self):
        self.hold()
        rows = self.st.list()
        self.assertEqual(len(rows), 1)
        self.assertNotIn("Tr0ub4dor", json.dumps(rows, ensure_ascii=False))

    # ---------------------------------------------------------------- 状态机
    def test_approve_returns_original_payload(self):
        rec = self.hold()
        view, payload = self.st.approve(rec["id"], by="user:admin",
                                        reason="客户已书面授权")
        self.assertEqual(payload, _payload())
        self.assertEqual(view["status"], ST_APPROVED)
        self.assertEqual(view["decided_by"], "user:admin")

    def test_approve_requires_meaningful_reason(self):
        rec = self.hold()
        with self.assertRaises(ApprovalError):
            self.st.approve(rec["id"], by="u", reason="好")

    def test_cannot_decide_twice(self):
        rec = self.hold()
        self.st.approve(rec["id"], by="u", reason="授权范围内")
        with self.assertRaises(ApprovalError) as ctx:
            self.st.approve(rec["id"], by="u", reason="再来一次")
        self.assertIn("approved", str(ctx.exception))

    def test_deny_destroys_body(self):
        rec = self.hold()
        view = self.st.deny(rec["id"], by="u", reason="不许外发")
        self.assertEqual(view["status"], ST_DENIED)
        self.assertEqual(view["bytes"], 0)
        with self.assertRaises(ApprovalError) as ctx:
            self.st.preview(rec["id"])
        self.assertIn("拒绝", str(ctx.exception))

    def test_sent_clears_body_and_is_terminal(self):
        rec = self.hold()
        self.st.approve(rec["id"], by="u", reason="授权范围内")
        view = self.st.mark_sent(rec["id"], "msg-123")
        self.assertEqual(view["status"], ST_SENT)
        self.assertEqual(view["message_id"], "msg-123")
        self.assertEqual(view["bytes"], 0)
        with self.assertRaises(ApprovalError):
            self.st.preview(rec["id"])

    def test_approved_without_sent_is_visible_as_backlog(self):
        """批准 ≠ 发出。停在 approved 的必须能被统计出来。"""
        rec = self.hold()
        self.st.approve(rec["id"], by="u", reason="授权范围内")
        self.assertEqual(self.st.stats()["counts"][ST_APPROVED], 1)
        self.assertEqual(self.st.stats()["counts"][ST_SENT], 0)

    def test_cannot_mark_sent_before_approval(self):
        rec = self.hold()
        with self.assertRaises(ApprovalError):
            self.st.mark_sent(rec["id"])

    # ---------------------------------------------------------------- 过期
    def test_expired_is_marked_not_deleted(self):
        rec = self.hold()
        n = self.st.purge_expired(now=time.time() + 10 ** 6)
        self.assertEqual(n, 1)
        view = self.st.get(rec["id"])
        self.assertEqual(view["status"], ST_EXPIRED)
        self.assertEqual(view["bytes"], 0)
        # 记录还在：删掉就查不到"有东西挂在这里没人管"这件事了
        self.assertTrue(os.path.exists(os.path.join(self.st.dir, f"{rec['id']}.json")))

    def test_expired_cannot_be_approved(self):
        rec = self.hold()
        self.st.purge_expired(now=time.time() + 10 ** 6)
        with self.assertRaises(ApprovalError):
            self.st.approve(rec["id"], by="u", reason="过期了还想批")

    # ---------------------------------------------------------------- 其他
    def test_illegal_id_rejected(self):
        for bad in ("", "../../etc/passwd", "apv-xyz", "apv-" + "a" * 25):
            with self.assertRaises(ApprovalError):
                self.st.get(bad)

    def test_list_filters_by_status(self):
        a = self.hold()
        b = self.hold()
        self.st.deny(b["id"], by="u", reason="不许")
        self.assertEqual([r["id"] for r in self.st.list(status=ST_PENDING)], [a["id"]])
        self.assertEqual([r["id"] for r in self.st.list(status=ST_DENIED)], [b["id"]])

    def test_unknown_status_rejected(self):
        with self.assertRaises(ApprovalError):
            self.st.list(status="whatever")

    def test_stats_shape(self):
        self.hold()
        s = self.st.stats()
        self.assertEqual(s["pending"], 1)
        self.assertIsNotNone(s["oldest_pending"])

    def test_replay_context_is_whitelisted(self):
        rec = self.hold(replay={"ttl_seconds": 600, "ttl_hops": 2,
                                "evil": "drop table"})
        self.assertEqual(rec["replay"], {"ttl_seconds": 600, "ttl_hops": 2})


if __name__ == "__main__":
    unittest.main()
