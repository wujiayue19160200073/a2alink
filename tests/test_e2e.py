"""端到端测试：真起一个注册中心，真走 HTTP，验准入策略。"""

import os
import socket
import sys
import tempfile
import threading
import time
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from a2alink.client import AgentLink, EgressBlocked, LinkError
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


class Base(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="a2alink-test-")
        cls.port = free_port()
        cls.reg = Registry(os.path.join(cls.tmp, "t.sqlite3"))
        cls.srv = make_server(cls.reg, "127.0.0.1", cls.port)
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()
        cls.url = f"http://127.0.0.1:{cls.port}"
        time.sleep(0.15)

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()
        cls.srv.server_close()   # shutdown 不关监听 socket
        cls.reg.close()          # 不关就靠 GC，测试跑多了会攒出 fd 泄漏

    def client(self, name, caps=()):
        return AgentLink(registry=self.url, name=name, capabilities=list(caps),
                         home=os.path.join(self.tmp, f"h_{name}"))

    def befriend(self, a, b):
        a.friend_request(b.name)
        b.friend_accept(b.pending_requests()[0]["id"])

    def admit(self, inviter, gid, invitee_name, invitee, voters=()):
        """完整准入三步：邀请 → 受邀者本人同意 → 成员表决。"""
        p = inviter.group_invite(gid, invitee_name)
        self.assertEqual(p["state"], "pending_consent")
        r = invitee.group_consent(gid, p["proposal_id"], True)
        for v in voters:
            r = v.group_vote(gid, p["proposal_id"], "yes")
        return r


class TestRegistryE2E(Base):
    def test_register_and_discover(self):
        a = self.client("reg-a", ["k8s"])
        self.assertTrue(a.agent_id.startswith("agt-"))
        found = a.discover(capability="k8s")
        self.assertTrue(any(x["name"] == "reg-a" for x in found))
        # token 绝不出现在公开发现结果里
        self.assertNotIn("token", str(found))

    def test_duplicate_name_rejected(self):
        AgentLink(registry=self.url, name="dup-name", home=os.path.join(self.tmp, "h_dup1"))
        with self.assertRaises(LinkError) as cm:
            AgentLink(registry=self.url, name="dup-name", home=os.path.join(self.tmp, "h_dup2"))
        self.assertEqual(cm.exception.code, "name_taken")

    def test_message_requires_friendship(self):
        a, b = self.client("fs-a"), self.client("fs-b")
        with self.assertRaises(LinkError) as cm:
            a.send_text("fs-b", "你好，还没加好友")
        self.assertEqual(cm.exception.code, "not_friends")

    def test_friend_flow_and_message(self):
        a, b = self.client("fr-a"), self.client("fr-b")
        req = a.friend_request("fr-b", "合作一下")
        self.assertEqual(req["state"], "pending")
        pend = b.pending_requests()
        self.assertEqual(pend[0]["from_agent"], a.agent_id)
        b.friend_accept(pend[0]["id"])
        self.assertEqual(len(a.friends()), 1)

        s = a.send_text("fr-b", "查一下 502 根因")
        self.assertEqual(s.delivered_to, 1)
        got = b.recv(limit=5)
        self.assertEqual(len(got), 1)
        self.assertEqual(got[0].env.from_agent, a.agent_id)
        # 围栏必须存在
        self.assertIn("<untrusted_external_content", got[0].text)

        # 回信结束会话
        b.reply(got[0], {"status": "ok", "summary": "上游限流"}, stage="done")
        back = a.recv(limit=5)
        self.assertEqual(back[0].env.stage, "done")
        self.assertEqual(back[0].env.in_reply_to, got[0].env.id)
        self.assertEqual(back[0].env.ttl_hops, got[0].env.ttl_hops - 1)

    def test_unfriend_blocks_immediately(self):
        a, b = self.client("uf-a"), self.client("uf-b")
        req = a.friend_request("uf-b")
        b.friend_accept(b.pending_requests()[0]["id"])
        a.send_text("uf-b", "第一条")
        a.unfriend("uf-b")
        with self.assertRaises(LinkError) as cm:
            a.send_text("uf-b", "第二条")
        self.assertEqual(cm.exception.code, "not_friends")

    def test_idempotency_dedup(self):
        a, b = self.client("id-a"), self.client("id-b")
        a.friend_request("id-b")
        b.friend_accept(b.pending_requests()[0]["id"])
        s1 = a.send_text("id-b", "同一个动作")
        # 手工重放同一封信
        out = a._api("POST", "/v1/messages", {"envelope": s1.env.to_dict()})
        self.assertTrue(out.get("duplicate"))
        self.assertEqual(len(b.recv(limit=10)), 1)

    def test_not_a_member_cannot_post(self):
        a = self.client("gm-a")
        c = self.client("gm-c")
        g = a.group_create("别拉我", join_mode="unan")
        with self.assertRaises(LinkError) as cm:
            c.send_text(g["group_id"], "我要说话")
        self.assertEqual(cm.exception.code, "not_member")

    def test_unanimous_vote_requires_all(self):
        owner, m1, m2 = self.client("v-o"), self.client("v-1"), self.client("v-2")
        g = owner.group_create("投票组", join_mode="unan")
        gid = g["group_id"]
        r = self.admit(owner, gid, "v-1", m1, voters=[owner])
        self.assertEqual(r["state"], "accepted")
        self.assertEqual(m1.group_info(gid)["members"][-1]["state"], "active")

        # 快照在"受邀者同意之后"才取，此刻群里有 2 人
        p2 = m1.group_invite(gid, "v-2")
        c2 = m2.group_consent(gid, p2["proposal_id"], True)
        self.assertEqual(c2["needed"], 2)
        self.assertEqual(c2["state"], "pending")
        v1 = m1.group_vote(gid, p2["proposal_id"], "yes")
        self.assertEqual(v1["state"], "pending")   # 一票不够
        v2 = owner.group_vote(gid, p2["proposal_id"], "yes")
        self.assertEqual(v2["state"], "accepted")
        active = [m["agent_id"] for m in owner.group_info(gid)["members"]]
        self.assertIn(m2.agent_id, active)

    def test_invitee_consent_is_mandatory(self):
        """受邀者不表态 = 永远不进群。表决根本不会启动。"""
        o, guest = self.client("cs-o"), self.client("cs-g")
        gid = o.group_create("硬性同意组")["group_id"]
        p = o.group_invite(gid, "cs-g")
        self.assertEqual(p["state"], "pending_consent")
        self.assertEqual(p["admission"], "vote")
        # 邀请发起人自己也投不了票——还没进入表决阶段
        with self.assertRaises(LinkError) as cm:
            o.group_vote(gid, p["proposal_id"], "yes")
        self.assertEqual(cm.exception.code, "conflict")
        # 未表态前不是成员，发不了言，也看不到成员名单
        with self.assertRaises(LinkError):
            guest.send_text(gid, "我先进来了")
        info = guest.group_info(gid)           # 受邀者可见最小信息集
        self.assertIsNone(info["members"])
        self.assertEqual(info["member_count"], 1)
        # 明确拒绝 → 不进群
        r = guest.group_consent(gid, p["proposal_id"], False, "跟这个群没关系")
        self.assertEqual(r["state"], "declined")
        self.assertFalse(r["joined"])
        active = [m["agent_id"] for m in o.group_info(gid)["members"]]
        self.assertNotIn(guest.agent_id, active)

    def test_consent_only_by_invitee(self):
        """第三方不能替受邀者表态——否则"同意"两个字就白写了。"""
        o, guest, other = self.client("co-o"), self.client("co-g"), self.client("co-x")
        gid = o.group_create("代签组")["group_id"]
        p = o.group_invite(gid, "co-g")
        with self.assertRaises(LinkError) as cm:
            other.group_consent(gid, p["proposal_id"], True)
        self.assertEqual(cm.exception.code, "forbidden")
        with self.assertRaises(LinkError):     # 邀请人自己也不行
            o.group_consent(gid, p["proposal_id"], True)

    def test_trusted_friend_joins_directly(self):
        """已是双向好友 → 跳过全员表决，受邀者点同意即可进群。"""
        o, pal = self.client("tr-o"), self.client("tr-p")
        self.befriend(o, pal)
        gid = o.group_create("好友组", join_mode="unan")["group_id"]
        p = o.group_invite(gid, "tr-p")
        self.assertEqual(p["admission"], "trusted")
        r = pal.group_consent(gid, p["proposal_id"], True)
        self.assertEqual(r["state"], "accepted")
        self.assertTrue(r["joined"])
        self.assertEqual(r["admission"], "trusted")
        active = [m["agent_id"] for m in o.group_info(gid)["members"]]
        self.assertIn(pal.agent_id, active)

    def test_trusted_direct_can_be_disabled(self):
        """群主可以关掉受信直入，全员回到表决流程。"""
        o, pal = self.client("td-o"), self.client("td-p")
        self.befriend(o, pal)
        gid = o.group_create("保守组", trusted_direct=False)["group_id"]
        p = o.group_invite(gid, "td-p")
        self.assertEqual(p["admission"], "vote")

    def test_decline_then_cooldown(self):
        """被拒之后不能立刻再敲一次门。"""
        o, guest = self.client("cd-o"), self.client("cd-g")
        gid = o.group_create("冷却组")["group_id"]
        p = o.group_invite(gid, "cd-g")
        guest.group_consent(gid, p["proposal_id"], False)
        with self.assertRaises(LinkError) as cm:
            o.group_invite(gid, "cd-g")
        self.assertEqual(cm.exception.code, "invite_cooldown")

    def test_pending_actions_lists_my_todo(self):
        o, guest = self.client("pd-o"), self.client("pd-g")
        gid = o.group_create("待办组")["group_id"]
        o.group_invite(gid, "pd-g")
        todo = guest.pending_actions()
        self.assertEqual(todo["count"], 1)
        self.assertEqual(todo["invites"][0]["group_name"], "待办组")

    def test_one_veto_blocks_unanimous(self):
        """全员表决模式下，任何一票 no 立即否决——这是一票否决的准确语义。"""
        o = self.client("x-o")
        m1 = self.client("x-1")
        m2 = self.client("x-2")
        m3 = self.client("x-3")
        g = o.group_create("否决组", join_mode="unan")
        gid = g["group_id"]

        self.assertEqual(self.admit(o, gid, "x-1", m1, [o])["state"], "accepted")
        self.assertEqual(self.admit(o, gid, "x-2", m2, [o, m1])["state"], "accepted")
        # 3 人组邀第 4 人 → 需要 3 票，先投 1 票
        p3 = o.group_invite(gid, "x-3")
        c3 = m3.group_consent(gid, p3["proposal_id"], True)
        self.assertEqual(c3["needed"], 3)
        self.assertEqual(o.group_vote(gid, p3["proposal_id"], "yes")["state"], "pending")
        r = m1.group_vote(gid, p3["proposal_id"], "no")
        self.assertEqual(r["state"], "rejected")
        active = [x["agent_id"] for x in o.group_info(gid)["members"]]
        self.assertNotIn(m3.agent_id, active)

    def test_majority_resolves_early(self):
        o = self.client("mj-o")
        a1 = self.client("mj-1")
        a2 = self.client("mj-2")
        a3 = self.client("mj-3")
        g = o.group_create("多数决", join_mode="majority")
        gid = g["group_id"]
        self.admit(o, gid, "mj-1", a1, [o])
        self.admit(o, gid, "mj-2", a2, [o])
        # 现在 3 人，邀第 4 人需要 2 票
        p = o.group_invite(gid, "mj-3")
        c = a3.group_consent(gid, p["proposal_id"], True)
        self.assertEqual(c["needed"], 2)
        r1 = o.group_vote(gid, p["proposal_id"], "yes")
        self.assertEqual(r1["state"], "pending")
        r2 = a1.group_vote(gid, p["proposal_id"], "yes")
        self.assertEqual(r2["state"], "accepted")

    def test_member_leave_unblocks_pending_proposal(self):
        """成员退出后，未结提案的快照要同步收缩，否则全员表决永久挂起。"""
        o = self.client("lv-o")
        a1 = self.client("lv-1")
        a2 = self.client("lv-2")
        g = o.group_create("离群组", join_mode="unan")
        gid = g["group_id"]
        self.admit(o, gid, "lv-1", a1, [o])
        p2 = o.group_invite(gid, "lv-2")
        c2 = a2.group_consent(gid, p2["proposal_id"], True)   # 快照 = [o, lv-1]，需 2 票
        self.assertEqual(c2["needed"], 2)
        o.group_vote(gid, p2["proposal_id"], "yes")
        props = {x["id"]: x for x in o.group_proposals(gid)}
        self.assertEqual(props[p2["proposal_id"]]["state"], "pending")
        # lv-1 退群后，快照收缩为 [o]，已有 1 票 → 应立即结案而不是挂起
        o.group_remove(gid, "lv-1")
        props = {x["id"]: x for x in o.group_proposals(gid)}
        self.assertNotIn(a1.agent_id, props[p2["proposal_id"]]["snapshot"])
        self.assertEqual(props[p2["proposal_id"]]["state"], "accepted")

    def test_egress_blocks_before_network(self):
        a, b = self.client("eg-a"), self.client("eg-b")
        a.friend_request("eg-b")
        b.friend_accept(b.pending_requests()[0]["id"])
        before = self.reg.stats()["messages"]
        with self.assertRaises(EgressBlocked):
            a.send_text("eg-b", "服务器 10.1.2.3 的 key 是 sk-abcdefghijklmnopqrstuvwxyz")
        self.assertEqual(self.reg.stats()["messages"], before)  # 没落库，说明没发出去

    def test_group_message_fans_out(self):
        o = self.client("fan-o")
        a1 = self.client("fan-1")
        g = o.group_create("广播组", join_mode="unan")
        gid = g["group_id"]
        self.admit(o, gid, "fan-1", a1, [o])
        s = o.send_text(gid, "群里的第一条通知", act="event")
        self.assertEqual(s.delivered_to, 1)
        self.assertEqual(len(a1.recv(limit=5)), 1)

    def test_bad_envelope_rejected(self):
        a = self.client("bd-a")
        with self.assertRaises(LinkError) as cm:
            a._api("POST", "/v1/messages", {"envelope": {"v": "1"}})
        self.assertEqual(cm.exception.code, "bad_envelope")

    def test_impersonation_rejected(self):
        a = self.client("im-a")
        b = self.client("im-b")
        a.friend_request("im-b")
        b.friend_accept(b.pending_requests()[0]["id"])
        s = a.send_text("im-b", "正常消息")
        d = s.env.to_dict()
        d["from"] = b.agent_id          # 冒名
        with self.assertRaises(LinkError) as cm:
            a._api("POST", "/v1/messages", {"envelope": d})
        self.assertEqual(cm.exception.code, "forbidden")

    def test_unauthorized(self):
        a = self.client("au-a")
        a.token = "a2a_forged_token_value_000000000000"
        with self.assertRaises(LinkError) as cm:
            a.friends()
        self.assertEqual(cm.exception.code, "unauthorized")


class TestRegistryDirect(unittest.TestCase):
    def test_invite_code_required(self):
        tmp = tempfile.mkdtemp()
        reg = Registry(os.path.join(tmp, "i.sqlite3"), invite_code="s3cret")
        self.addCleanup(reg.close)
        with self.assertRaises(Exception):
            reg.register("nope", [])
        out = reg.register("yep", [], invite_code="s3cret")
        self.assertTrue(out["agent_id"])

    def test_audit_written(self):
        tmp = tempfile.mkdtemp()
        reg = Registry(os.path.join(tmp, "a.sqlite3"))
        self.addCleanup(reg.close)
        reg.register("audit-a", [])
        log = reg.audit_log(10)
        self.assertTrue(any(x["action"] == "register" for x in log))


class TestAuditTrail(unittest.TestCase):
    """"不让管家推卸责任"的验收：闸门每一次动作都要在链上留下痕迹。"""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp()
        cls.reg = Registry(os.path.join(cls.tmp, "aud.sqlite3"))
        cls.srv = make_server(cls.reg, port=0)
        cls.port = cls.srv.server_address[1]
        cls.url = f"http://127.0.0.1:{cls.port}"
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()
        cls.srv.server_close()   # shutdown 不关监听 socket
        cls.reg.close()          # 不关就靠 GC，测试跑多了会攒出 fd 泄漏

    def client(self, name):
        return AgentLink(registry=self.url, name=name,
                         home=os.path.join(self.tmp, f"h_{name}"))

    def befriend(self, a, b):
        a.friend_request(b.name)
        b.friend_accept(b.pending_requests()[0]["id"])

    def test_blocked_message_is_audited_with_reason_code(self):
        a, b = self.client("au-a"), self.client("au-b")
        self.befriend(a, b)
        # v0.5 起默认行为是"挂起等人批准"，不再是直接丢弃；
        # 所以理由码从 egress.deny 变成 gate.hold。留痕这条要求没变。
        with self.assertRaises(EgressBlocked):
            a.send_text("au-b", "key 是 AKIAIOSFODNN7EXAMPLE")
        recs = a.audit.read(limit=50, decision="note")
        hit = [r for r in recs if r["reason"] == "gate.hold"]
        self.assertTrue(hit, "挂起必须留下理由码记录")
        self.assertIn("cloud_ak", hit[0]["detail"]["rules"])
        self.assertTrue(hit[0]["detail"].get("pending"), "记录里要有审批件 ID 才能追踪")
        # 记录里不能有明文密钥
        with open(a.audit._path, encoding="utf-8") as fh:
            raw = fh.read()
        self.assertNotIn("AKIAIOSFODNN7EXAMPLE", raw)

    def test_force_without_reason_is_refused_and_logged(self):
        a, b = self.client("fr-a"), self.client("fr-b")
        self.befriend(a, b)
        with self.assertRaises(LinkError) as cm:
            a.send_text("fr-b", "key 是 AKIAIOSFODNN7EXAMPLE", force=True)
        self.assertEqual(cm.exception.code, "force_requires_reason")
        recs = a.audit.read(limit=50, reason="egress.override")
        self.assertTrue(any(r["decision"] == "drop" for r in recs),
                        "无理由的强行放行尝试必须被记录下来")

    def test_force_with_reason_is_logged_with_reason_text(self):
        a, b = self.client("fok-a"), self.client("fok-b")
        self.befriend(a, b)
        why = "对方是甲方安全接口人，已电话确认可提供测试密钥"
        a.send_text("fok-b", "key 是 AKIAIOSFODNN7EXAMPLE",
                    force=True, force_reason=why)
        recs = a.audit.read(limit=50, reason="egress.override")
        rec = [r for r in recs if r["decision"] == "note"]
        self.assertTrue(rec, "强行放行必须留痕")
        self.assertEqual(rec[0]["detail"]["force_reason"], why)
        self.assertTrue(rec[0]["detail"]["human_confirmed"])

    def test_allowed_message_also_logged(self):
        """"通过了"也要记——否则无法自证"我查过"。"""
        a, b = self.client("ok-a"), self.client("ok-b")
        self.befriend(a, b)
        s = a.send_text("ok-b", "帮我看下 502")
        # 客户端本地
        recs = a.audit.read(limit=50, trace=s.env.trace_id)
        reasons = [r["reason"] for r in recs]
        self.assertIn("egress.allow", reasons)
        self.assertIn("watchdog.allow", reasons)
        self.assertIn("wire.sent", reasons)
        # 服务端同一 trace 也查得到
        tv = self.reg.trace_view(s.env.trace_id)
        self.assertTrue(tv["messages"])
        self.assertTrue(any(e.get("reason") == "server.accept" for e in tv["audit"]))

    def test_server_records_rejections(self):
        a = self.client("rj-a")
        with self.assertRaises(LinkError):
            a.send("agt-doesnotexist", {"instruction": "hi"})
        audit = self.reg.audit_log(50)
        rejects = [x for x in audit if x["action"] == "reject"]
        self.assertTrue(rejects, "服务端拒绝必须留痕")
        self.assertTrue(any(x["decision"] == "deny" for x in rejects))

    def test_purge_keeps_audit(self):
        """清理业务数据时不许顺手删审计——那是最好用的洗证据方式。"""
        tmp = tempfile.mkdtemp()
        reg = Registry(os.path.join(tmp, "p.sqlite3"))
        self.addCleanup(reg.close)
        reg.register("pa", [])
        before = len(reg.audit_log(200))
        reg.purge_old(days=0)
        after = len(reg.audit_log(200))
        self.assertGreaterEqual(after, before)


if __name__ == "__main__":
    unittest.main()
