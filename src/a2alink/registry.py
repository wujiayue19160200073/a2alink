"""A2A Link 注册中心（控制面）。

=========================== 架构定位 ===========================
这个进程只负责"谁能跟谁说话"，不负责"说了什么"。
   控制面（本文件）：身份、能力发现、好友关系、群成员、表决、准入策略
   数据面（client↔client）：真实消息载荷
原型阶段两者复用同一个 HTTP 口，但从一开始就分表、分权限、分审计日志，
将来把中继拆成独立网关时不需要改协议。

=========================== 为什么要"服务端强制" ===================
几乎所有的 A2A 原型都把"是不是好友"判断放在客户端 SDK 里。
这在公网上等价于没有：任何人拿到对方的 agent_id 就能私自发消息，
SDK 里的那几行 if 只是"礼貌"。
所以这里的原则是：**准入判定只在服务端做一次，客户端只做体验优化。**
客户端再判一遍，是为了少一次网络往返，不是安全边界。

=========================== 群表决的三个坑 =======================
1) 成员变动导致表决永久挂起 → 提案里保存成员快照（snapshot），成员退出时
   主动从所有未结提案快照中移除。
2) 全员表决在 5 人以上基本不可用（有人休假就卡死）→ 支持 unan/majority/admin
   三种模式，并给出 quorum 提前结案；文档里明确写"全员表决只适合 <=5 人核心组"。
3) 表决被投票垃圾和女巫账号刷穿 → 只有快照内的成员有投票权，且一人一票
   （PRIMARY KEY 约束），提案有 TTL。
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import secrets
import sqlite3
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Callable, Dict, List, Optional, Tuple
from urllib.parse import parse_qs, urlparse

from .audit import AuditLog
from .protocol import Envelope, ProtocolError, new_id

MAX_BODY = 1024 * 1024

# ---- 入群准入的两个时间参数（别写在函数里，方便运维调） ----
CONSENT_PENDING = "pending_consent"   # 等受邀者本人表态
CONSENT_TTL = 3 * 86400               # 邀请 72 小时不作废？不，是作废——防"半年后突然生效"
DECLINE_COOLDOWN = 86400              # 被拒后 24 小时内不得再邀请同一人
DECLINE_BLOCK_AFTER = 3               # 被同一人拒绝 3 次 → 冷却 7 天
INVITE_SENT_PER_DAY = 20              # 单 Agent 每天最多发起的好友申请数
ASK = ("pending", "accepted", "rejected", "expired", "cancelled")

SCHEMA = """
CREATE TABLE IF NOT EXISTS agents (
  id TEXT PRIMARY KEY,
  name TEXT UNIQUE NOT NULL,
  owner TEXT DEFAULT '',
  description TEXT DEFAULT '',
  capabilities TEXT DEFAULT '[]',
  endpoint TEXT DEFAULT '',
  token_hash TEXT NOT NULL,
  status TEXT DEFAULT 'active',
  created_at REAL NOT NULL,
  last_seen REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS friends (
  pair TEXT PRIMARY KEY,
  a TEXT NOT NULL,
  b TEXT NOT NULL,
  state TEXT NOT NULL,
  created_at REAL NOT NULL,
  updated_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS friend_requests (
  id TEXT PRIMARY KEY,
  from_agent TEXT NOT NULL,
  to_agent TEXT NOT NULL,
  message TEXT DEFAULT '',
  state TEXT NOT NULL,
  created_at REAL NOT NULL,
  responded_at REAL
);
CREATE TABLE IF NOT EXISTS groups (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  owner TEXT NOT NULL,
  join_mode TEXT NOT NULL,
  quorum REAL NOT NULL,
  proposal_ttl REAL NOT NULL,
  max_members INTEGER NOT NULL,
  on_timeout TEXT NOT NULL,
  created_at REAL NOT NULL,
  trusted_direct INTEGER NOT NULL DEFAULT 1,
  consent_ttl REAL NOT NULL DEFAULT 259200,
  invite_per_hour INTEGER NOT NULL DEFAULT 20
);
CREATE TABLE IF NOT EXISTS group_members (
  group_id TEXT NOT NULL,
  agent_id TEXT NOT NULL,
  role TEXT NOT NULL,
  state TEXT NOT NULL,
  joined_at REAL NOT NULL,
  PRIMARY KEY (group_id, agent_id)
);
CREATE TABLE IF NOT EXISTS proposals (
  id TEXT PRIMARY KEY,
  group_id TEXT NOT NULL,
  kind TEXT NOT NULL,
  target TEXT NOT NULL,
  created_by TEXT NOT NULL,
  mode TEXT NOT NULL,
  snapshot TEXT NOT NULL,
  state TEXT NOT NULL,
  created_at REAL NOT NULL,
  expires_at REAL NOT NULL,
  resolved_at REAL,
  admission TEXT NOT NULL DEFAULT 'vote',
  consent TEXT NOT NULL DEFAULT 'pending',
  consent_at REAL,
  consent_reason TEXT DEFAULT ''
);
CREATE TABLE IF NOT EXISTS votes (
  proposal_id TEXT NOT NULL,
  agent_id TEXT NOT NULL,
  vote TEXT NOT NULL,
  created_at REAL NOT NULL,
  PRIMARY KEY (proposal_id, agent_id)
);
CREATE TABLE IF NOT EXISTS messages (
  seq INTEGER PRIMARY KEY AUTOINCREMENT,
  id TEXT UNIQUE NOT NULL,
  from_agent TEXT NOT NULL,
  to_type TEXT NOT NULL,
  to_id TEXT NOT NULL,
  conversation_id TEXT NOT NULL,
  envelope TEXT NOT NULL,
  created_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS deliveries (
  seq INTEGER PRIMARY KEY AUTOINCREMENT,
  message_seq INTEGER NOT NULL,
  recipient TEXT NOT NULL,
  state TEXT NOT NULL,
  created_at REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_deliv ON deliveries(recipient, seq);
CREATE TABLE IF NOT EXISTS idem (
  key TEXT PRIMARY KEY,
  message_id TEXT NOT NULL,
  created_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS audit (
  seq INTEGER PRIMARY KEY AUTOINCREMENT,
  ts REAL NOT NULL,
  actor TEXT,
  action TEXT NOT NULL,
  detail TEXT DEFAULT ''
);
"""


class RegistryError(Exception):
    def __init__(self, code: str, message: str, status: int = 400) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.status = status


class Registry:
    def __init__(self, db_path: str = "a2alink.sqlite3",
                 invite_code: Optional[str] = None,
                 audit_enabled: bool = True) -> None:
        self.db_path = db_path
        d = os.path.dirname(os.path.abspath(db_path))
        if d:
            os.makedirs(d, exist_ok=True)
        self.conn = sqlite3.connect(db_path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA foreign_keys=ON")
        self.conn.execute("PRAGMA busy_timeout=5000")
        self.conn.executescript(SCHEMA)
        self.conn.commit()
        self.lock = threading.RLock()
        self._migrate()
        self.invite_code = invite_code
        self._rl: Dict[str, List[float]] = {}
        # 服务端审计也落一条哈希链。为什么不只靠 SQLite：
        # 数据库是"可 UPDATE、可 DELETE"的东西，一句 UPDATE audit SET detail=...
        # 就能把证据改成对自己有利的样子，而没人看得出来。
        # JSONL 哈希链的作用就是让"改过"这件事本身留下痕迹。
        self.audit_chain = AuditLog(
            os.path.join(d, "logs") if d else "logs", "service:registry",
            preview_chars=0, enabled=audit_enabled)

    # 老库升级：v0.1.1 给 proposals/groups 加了字段，直接 ALTER 补上，
    # 不搞"删库重建"——那是在教用户丢数据。
    _MIGRATIONS = (
        ("groups", "trusted_direct", "INTEGER NOT NULL DEFAULT 1"),
        ("groups", "consent_ttl", "REAL NOT NULL DEFAULT 259200"),
        ("groups", "invite_per_hour", "INTEGER NOT NULL DEFAULT 20"),
        ("proposals", "admission", "TEXT NOT NULL DEFAULT 'vote'"),
        ("proposals", "consent", "TEXT NOT NULL DEFAULT 'pending'"),
        ("proposals", "consent_at", "REAL"),
        ("proposals", "consent_reason", "TEXT DEFAULT ''"),
        # v0.1.2 审计可追责：给消息打 trace、给投递留失败原因、给审计加结构化字段。
        # 老库直接补列，不重建表——审计表一旦重建，历史证据就没了。
        ("messages", "trace_id", "TEXT DEFAULT ''"),
        ("deliveries", "reason", "TEXT DEFAULT ''"),
        ("audit", "decision", "TEXT DEFAULT 'note'"),
        ("audit", "reason", "TEXT DEFAULT ''"),
        ("audit", "trace", "TEXT DEFAULT ''"),
    )

    def _migrate(self) -> None:
        for table, col, decl in self._MIGRATIONS:
            cols = {r["name"] for r in self._q(f"PRAGMA table_info({table})")}
            if col not in cols:
                self.conn.execute(f"ALTER TABLE {table} ADD COLUMN {col} {decl}")
        self.conn.commit()

    # ------------------------------------------------------------------
    # 基础设施
    # ------------------------------------------------------------------
    def _q(self, sql: str, args: Tuple = ()) -> List[sqlite3.Row]:
        with self.lock:
            return list(self.conn.execute(sql, args).fetchall())

    def _x(self, sql: str, args: Tuple = ()) -> sqlite3.Cursor:
        with self.lock:
            cur = self.conn.execute(sql, args)
            self.conn.commit()
            return cur

    def audit(self, actor: Optional[str], action: str, detail: str = "", *,
              decision: str = "note", reason: str = "server.accept",
              trace: str = "", extra: Optional[Dict[str, Any]] = None) -> None:
        """服务端审计：SQLite 便于查询，JSONL 哈希链便于证明"没被改过"。

        两处都写，不是因为冗余，是因为它们回答的是不同问题：
        数据库回答"发生了什么"，哈希链回答"记录有没有被动过"。
        只留数据库，一句 UPDATE 就能把拒绝改成通过，事后无从分辨。
        """
        now = time.time()
        payload: Dict[str, Any] = {"action": action}
        if extra:
            payload.update(extra)
        try:
            self._x("""INSERT INTO audit(ts,actor,action,detail,decision,reason,trace)
                       VALUES (?,?,?,?,?,?,?)""",
                    (now, actor, action, detail[:2000], decision, reason, trace))
        except sqlite3.Error:
            pass    # 审计表异常不应打断业务；哈希链那条仍然会落盘
        self.audit_chain.write(f"server.{action}", decision, reason, trace=trace,
                             detail=payload, preview=detail)

    def rate_limit(self, agent_id: str, per_minute: int = 120) -> None:
        now = time.time()
        with self.lock:
            q = [t for t in self._rl.get(agent_id, []) if now - t < 60]
            if len(q) >= per_minute:
                raise RegistryError("rate_limited", "请求过于频繁，已被限流", 429)
            q.append(now)
            self._rl[agent_id] = q

    @staticmethod
    def _hash(token: str) -> str:
        return hashlib.sha256(token.encode("utf-8")).hexdigest()

    # ------------------------------------------------------------------
    # 身份
    # ------------------------------------------------------------------
    def register(self, name: str, capabilities: List[str], owner: str = "",
                 description: str = "", endpoint: str = "",
                 invite_code: Optional[str] = None) -> Dict[str, Any]:
        if self.invite_code and not hmac.compare_digest(
                str(invite_code or ""), self.invite_code):
            raise RegistryError("invite_required", "注册需要有效邀请码", 403)
        if not re.fullmatch(r"[A-Za-z0-9_\-\u4e00-\u9fa5]{2,40}", name or ""):
            raise RegistryError("bad_name", "名称 2-40 字符，仅允许中英文/数字/_-")
        caps = [c.strip() for c in (capabilities or []) if c and c.strip()][:20]
        if len(json.dumps(caps, ensure_ascii=False)) > 2000:
            raise RegistryError("caps_too_large", "能力标签过长")
        now = time.time()
        agent_id = new_id("agt-")
        token = "a2a_" + secrets.token_urlsafe(32)
        with self.lock:
            if self._q("SELECT 1 FROM agents WHERE name=?", (name,)):
                raise RegistryError("name_taken", "名称已被占用，请换一个", 409)
            self._x("""INSERT INTO agents(id,name,owner,description,capabilities,
                       endpoint,token_hash,status,created_at,last_seen)
                       VALUES (?,?,?,?,?,?,?,?,?,?)""",
                    (agent_id, name, owner[:120], description[:500],
                     json.dumps(caps, ensure_ascii=False), endpoint[:300],
                     self._hash(token), "active", now, now))
        self.audit(agent_id, "register", f"name={name}")
        return {"agent_id": agent_id, "name": name, "token": token,
                "capabilities": caps,
                "note": "token 只返回这一次，请立刻保存到本地，不要提交到代码仓库"}

    def auth(self, token: Optional[str]) -> sqlite3.Row:
        if not token:
            raise RegistryError("unauthorized", "缺少 Authorization: Bearer <token>", 401)
        rows = self._q("SELECT * FROM agents WHERE token_hash=?", (self._hash(token),))
        if not rows:
            raise RegistryError("unauthorized", "token 无效", 401)
        row = rows[0]
        if row["status"] != "active":
            raise RegistryError("forbidden", "该 Agent 已被停用", 403)
        return row

    def touch(self, agent_id: str) -> None:
        self._x("UPDATE agents SET last_seen=? WHERE id=?", (time.time(), agent_id))

    def public_agent(self, row: sqlite3.Row) -> Dict[str, Any]:
        """对外只暴露发现所需字段。token_hash / owner 绝不外泄。"""
        return {"agent_id": row["id"], "name": row["name"],
                "description": row["description"],
                "capabilities": json.loads(row["capabilities"] or "[]"),
                "last_seen": row["last_seen"]}

    def discover(self, capability: Optional[str], q: Optional[str],
                 limit: int = 50) -> List[Dict[str, Any]]:
        sql = "SELECT * FROM agents WHERE status='active'"
        args: List[Any] = []
        if q:
            sql += " AND (name LIKE ? OR description LIKE ?)"
            args += [f"%{q}%", f"%{q}%"]
        sql += " ORDER BY last_seen DESC LIMIT ?"
        args.append(max(1, min(200, limit)))
        rows = self._q(sql, tuple(args))
        out = [self.public_agent(r) for r in rows]
        if capability:
            out = [a for a in out if capability in a["capabilities"]]
        return out

    # ------------------------------------------------------------------
    # 好友（双向同意）
    # ------------------------------------------------------------------
    @staticmethod
    def _pair(a: str, b: str) -> str:
        return "|".join(sorted([a, b]))

    def friend_request(self, frm: str, to: str, message: str = "") -> Dict[str, Any]:
        if frm == to:
            raise RegistryError("bad_request", "不能加自己为好友")
        if not self._q("SELECT 1 FROM agents WHERE id=? AND status='active'", (to,)):
            raise RegistryError("not_found", "目标 Agent 不存在或已停用", 404)
        if self._friend_state(frm, to) == "accepted":
            raise RegistryError("already_friends", "你们已经是好友", 409)
        now = time.time()
        # 反滥用①：全局配额。没有它，一个 Agent 一晚上能给全网每个 Agent 发一次好友申请。
        sent = self._q("""SELECT COUNT(*) c FROM friend_requests
                          WHERE from_agent=? AND created_at>?""",
                       (frm, now - 86400))[0]["c"]
        if sent >= INVITE_SENT_PER_DAY:
            raise RegistryError("friend_quota_exhausted",
                                f"24 小时内好友申请已达上限 {INVITE_SENT_PER_DAY} 条", 429)
        # 反滥用②：对方连续拒绝 3 次后停手（不然就是骚扰）
        rej = self._q("""SELECT COUNT(*) c FROM friend_requests
                         WHERE from_agent=? AND to_agent=? AND state='rejected'""",
                      (frm, to))[0]["c"]
        if rej >= 3:
            raise RegistryError("blocked_by_target",
                                "对方已多次拒绝，请勿继续申请", 403)
        # 反骚扰：同一对 24 小时内最多 3 次
        recent = self._q("""SELECT COUNT(*) c FROM friend_requests
                            WHERE from_agent=? AND to_agent=? AND created_at>?""",
                         (frm, to, now - 86400))
        if recent and recent[0]["c"] >= 3:
            raise RegistryError("too_many_requests", "24 小时内请求次数过多", 429)
        rid = new_id("frq-")
        self._x("""INSERT INTO friend_requests(id,from_agent,to_agent,message,state,created_at)
                   VALUES (?,?,?,?,?,?)""", (rid, frm, to, message[:500], "pending", now))
        self.audit(frm, "friend_request", f"to={to}")
        return {"request_id": rid, "state": "pending",
                "note": "已发出，等待对方同意。未同意前双方无法互发消息。"}

    def _friend_state(self, a: str, b: str) -> Optional[str]:
        rows = self._q("SELECT state FROM friends WHERE pair=?", (self._pair(a, b),))
        return rows[0]["state"] if rows else None

    def friend_respond(self, me: str, request_id: str, accept: bool) -> Dict[str, Any]:
        rows = self._q("SELECT * FROM friend_requests WHERE id=?", (request_id,))
        if not rows:
            raise RegistryError("not_found", "请求不存在", 404)
        r = rows[0]
        if r["to_agent"] != me:
            raise RegistryError("forbidden", "只有被请求方可以处理", 403)
        if r["state"] != "pending":
            raise RegistryError("conflict", f"请求已是 {r['state']} 状态", 409)
        now = time.time()
        state = "accepted" if accept else "rejected"
        self._x("UPDATE friend_requests SET state=?, responded_at=? WHERE id=?",
                (state, now, request_id))
        if accept:
            pair = self._pair(r["from_agent"], me)
            a, b = sorted([r["from_agent"], me])
            self._x("""INSERT INTO friends(pair,a,b,state,created_at,updated_at)
                       VALUES (?,?,?,?,?,?)
                       ON CONFLICT(pair) DO UPDATE SET state='accepted', updated_at=?""",
                    (pair, a, b, "accepted", now, now, now))
        self.audit(me, "friend_respond", f"request={request_id} accept={accept}")
        return {"state": state, "peer": r["from_agent"]}

    def friends(self, me: str) -> List[Dict[str, Any]]:
        rows = self._q("SELECT * FROM friends WHERE (a=? OR b=?) AND state='accepted'", (me, me))
        out = []
        for r in rows:
            peer = r["b"] if r["a"] == me else r["a"]
            pr = self._q("SELECT * FROM agents WHERE id=?", (peer,))
            if pr:
                out.append({"peer": self.public_agent(pr[0]), "since": r["created_at"]})
        return out

    def unfriend(self, me: str, peer: str) -> Dict[str, Any]:
        self._x("DELETE FROM friends WHERE pair=?", (self._pair(me, peer),))
        self.audit(me, "unfriend", f"peer={peer}")
        return {"state": "removed"}

    def friend_requests(self, me: str, box: str = "in") -> List[Dict[str, Any]]:
        col = "to_agent" if box == "in" else "from_agent"
        rows = self._q(f"""SELECT * FROM friend_requests WHERE {col}=?
                           ORDER BY created_at DESC LIMIT 100""", (me,))
        return [dict(r) for r in rows]

    # ------------------------------------------------------------------
    # 群组 + 表决
    # ------------------------------------------------------------------
    def create_group(self, me: str, name: str, join_mode: str = "unan",
                     quorum: float = 0.0, proposal_ttl: float = 86400,
                     max_members: int = 50, on_timeout: str = "reject",
                     trusted_direct: bool = True,
                     consent_ttl: float = CONSENT_TTL,
                     invite_per_hour: int = 20) -> Dict[str, Any]:
        if join_mode not in ("unan", "majority", "admin"):
            raise RegistryError("bad_request", "join_mode 只能是 unan/majority/admin")
        if on_timeout not in ("reject", "approve_if_quorum"):
            raise RegistryError("bad_request", "on_timeout 只能是 reject/approve_if_quorum")
        gid = new_id("grp-")
        now = time.time()
        self._x("""INSERT INTO groups(id,name,owner,join_mode,quorum,proposal_ttl,
                   max_members,on_timeout,created_at,trusted_direct,consent_ttl,
                   invite_per_hour) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
                (gid, (name or "未命名群")[:80], me, join_mode,
                 float(quorum), float(proposal_ttl), int(max_members), on_timeout, now,
                 1 if trusted_direct else 0, float(consent_ttl), int(invite_per_hour)))
        self._x("""INSERT INTO group_members(group_id,agent_id,role,state,joined_at)
                   VALUES (?,?,?,?,?)""", (gid, me, "owner", "active", now))
        self.audit(me, "group_create", f"{gid} mode={join_mode} trusted={trusted_direct}")
        return {"group_id": gid, "join_mode": join_mode,
                "trusted_direct": bool(trusted_direct),
                "consent_ttl": float(consent_ttl),
                "hint": "两段式准入：① 受邀者本人同意（不可关闭）② 再按 join_mode 表决。"
                        "trusted_direct=1 时，若邀请人与受邀者已是好友，第②段直接跳过。"}

    def _member(self, gid: str, aid: str) -> Optional[sqlite3.Row]:
        rows = self._q("SELECT * FROM group_members WHERE group_id=? AND agent_id=?",
                       (gid, aid))
        return rows[0] if rows else None

    def group_members(self, gid: str) -> List[Dict[str, Any]]:
        rows = self._q("""SELECT * FROM group_members WHERE group_id=?
                          ORDER BY joined_at""", (gid,))
        return [dict(r) for r in rows]

    def group_info(self, gid: str) -> Dict[str, Any]:
        rows = self._q("SELECT * FROM groups WHERE id=?", (gid,))
        if not rows:
            raise RegistryError("not_found", "群不存在", 404)
        g = dict(rows[0])
        g["members"] = self.group_members(gid)
        g["pending_proposals"] = [p for p in self.list_proposals(gid)
                                  if p["state"] in ("pending", CONSENT_PENDING)]
        return g

    def group_public_info(self, gid: str) -> Dict[str, Any]:
        """给「被邀请但还没进群」的人看的最小信息集。

        刻意**不含成员名单**：让人先看到"我会跟谁在一个群里"，是一个侦察入口。
        只给人数、群主公号、建群时间和邀请人——够判断要不要同意，不够做情报收集。
        """
        rows = self._q("SELECT * FROM groups WHERE id=?", (gid,))
        if not rows:
            raise RegistryError("not_found", "群不存在", 404)
        g = rows[0]
        n = self._q("SELECT COUNT(*) c FROM group_members WHERE group_id=? AND state='active'",
                    (gid,))[0]["c"]
        return {"group_id": gid, "name": g["name"], "owner": g["owner"],
                "member_count": n, "join_mode": g["join_mode"],
                "created_at": g["created_at"], "members": None,
                "note": "成员名单对非成员不可见；入群后才能看到"}

    def invitee(self, gid: str, aid: str) -> bool:
        """aid 是否有未结的入群邀请（用于给受邀者开一个"最小可见窗口"）。"""
        return bool(self._q("""SELECT 1 FROM proposals WHERE group_id=? AND target=?
                               AND state=? LIMIT 1""", (gid, aid, CONSENT_PENDING)))

    def invite(self, me: str, gid: str, target: str) -> Dict[str, Any]:
        g = self._q("SELECT * FROM groups WHERE id=?", (gid,))
        if not g:
            raise RegistryError("not_found", "群不存在", 404)
        g = g[0]
        m = self._member(gid, me)
        if not m or m["state"] != "active":
            raise RegistryError("forbidden", "你不在这个群里", 403)
        if not self._q("SELECT 1 FROM agents WHERE id=? AND status='active'", (target,)):
            raise RegistryError("not_found", "目标 Agent 不存在", 404)
        exist = self._member(gid, target)
        if exist and exist["state"] == "active":
            raise RegistryError("already_member", "已经是成员", 409)

        now = time.time()
        # 幂等：已有未结邀请就别再生成一条（否则一人一天点十次会刷爆对方的待办）
        dup = self._q("""SELECT * FROM proposals WHERE group_id=? AND target=?
                         AND state IN (?, 'pending')""", (gid, target, CONSENT_PENDING))
        if dup:
            p = dup[0]
            return {"proposal_id": p["id"], "state": p["state"],
                    "admission": p["admission"], "mode": p["mode"],
                    "duplicate": True, "hint": "已有未结邀请，未重复创建"}

        active = [r["agent_id"] for r in self._q(
            "SELECT agent_id FROM group_members WHERE group_id=? AND state='active'", (gid,))]
        if len(active) >= g["max_members"]:
            raise RegistryError("group_full", f"群成员已达上限 {g['max_members']}", 409)

        # 反滥用①：邀请配额。没有这条，"一个人把半个注册中心拉进一个群"只要几秒。
        cnt = self._q("SELECT COUNT(*) c FROM proposals WHERE group_id=? AND created_at>?",
                      (gid, now - 3600))[0]["c"]
        if cnt >= int(g["invite_per_hour"]):
            raise RegistryError("invite_rate_limited",
                                f"本群每小时邀请上限 {g['invite_per_hour']} 次，请稍后再试", 429)

        # 反滥用②：对方拒过就别再敲。这是 IP 层做不到、协议层必须做的事。
        dq = self._q("""SELECT COUNT(*) c, MAX(consent_at) t FROM proposals
                        WHERE group_id=? AND target=? AND consent='declined'""", (gid, target))
        dc = dq[0]["c"] or 0
        if dc >= DECLINE_BLOCK_AFTER:
            raise RegistryError("blocked_by_target",
                                "对方已多次拒绝加入本群，进入 7 天冷却期", 403)
        if dc >= 1 and (dq[0]["t"] or 0) > now - DECLINE_COOLDOWN:
            raise RegistryError("invite_cooldown",
                                "对方刚拒绝过邀请，24 小时内不得重复邀请", 429)

        # 准入路径判定（三选一）
        friend = self._friend_state(me, target) == "accepted"
        if bool(g["trusted_direct"]) and friend:
            admission = "trusted"       # 双向好友 = 信任已建立 → 跳过全员表决
        elif g["join_mode"] == "admin" and m["role"] in ("owner", "admin"):
            admission = "admin"
        else:
            admission = "vote"

        pid = new_id("prp-")
        # 关键：**一律先等受邀者本人同意**。这一步对所有 admission 都成立，没有开关。
        # 快照留空——表决真正开始时才取，避免等待期间成员变动导致语义漂移。
        self._x("""INSERT INTO proposals(id,group_id,kind,target,created_by,mode,snapshot,
                   state,created_at,expires_at,resolved_at,admission,consent)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (pid, gid, "invite", target, me, g["join_mode"], json.dumps([]),
                 CONSENT_PENDING, now, now + float(g["consent_ttl"]), None,
                 admission, "pending"))
        self.audit(me, "group_invite", f"{gid} target={target} admission={admission}")
        return {"proposal_id": pid, "state": CONSENT_PENDING, "admission": admission,
                "mode": g["join_mode"], "consent_ttl": float(g["consent_ttl"]),
                "hint": "等待受邀者本人同意。对方不表态就永远不会入群，超时自动作废。"}

    def consent(self, me: str, gid: str, pid: str, accept: bool,
                reason: str = "") -> Dict[str, Any]:
        """受邀者表态。这是入群的**唯一**入口，也是唯一能拒绝入群的地方。"""
        rows = self._q("SELECT * FROM proposals WHERE id=? AND group_id=?", (pid, gid))
        if not rows:
            raise RegistryError("not_found", "提案不存在", 404)
        p = rows[0]
        if p["target"] != me:
            raise RegistryError("forbidden", "只有被邀请的 Agent 本人可以表态", 403)
        if p["state"] == "pending":
            raise RegistryError("conflict", "你已经同意过了，正在表决中", 409)
        if p["state"] != CONSENT_PENDING:
            raise RegistryError("conflict", f"提案已是 {p['state']} 状态", 409)
        now = time.time()
        if now > p["expires_at"]:
            self._x("UPDATE proposals SET state='expired_consent', consent='expired' "
                    "WHERE id=?", (pid,))
            raise RegistryError("expired", "邀请已过期，需要重新邀请", 409)

        if not accept:
            self._x("""UPDATE proposals SET state='declined', consent='declined',
                       consent_at=?, consent_reason=?, resolved_at=? WHERE id=?""",
                    (now, str(reason)[:300], now, pid))
            self.audit(me, "group_decline", f"{pid} reason={str(reason)[:80]}")
            return {"proposal_id": pid, "state": "declined", "joined": False,
                    "hint": "已拒绝，不会入群。同一邀请人 24 小时内不能再邀请你。"}

        g = self._q("SELECT * FROM groups WHERE id=?", (gid,))[0]
        self._x("UPDATE proposals SET consent='accepted', consent_at=? WHERE id=?",
                (now, pid))
        if p["admission"] in ("trusted", "admin"):
            self._x("UPDATE proposals SET state='accepted', resolved_at=? WHERE id=?",
                    (now, pid))
            self._x("""INSERT INTO group_members(group_id,agent_id,role,state,joined_at)
                       VALUES (?,?,?,?,?) ON CONFLICT(group_id,agent_id)
                       DO UPDATE SET state='active'""", (gid, me, "member", "active", now))
            self.audit(me, "group_join", f"{gid} via={p['admission']}")
            return {"proposal_id": pid, "state": "accepted", "joined": True,
                    "admission": p["admission"],
                    "hint": "已入群。受信直入：你与邀请人是双向好友，跳过了全员表决。"}

        # 走表决：快照在此刻取，而不是邀请时
        snapshot = [r["agent_id"] for r in self._q(
            "SELECT agent_id FROM group_members WHERE group_id=? AND state='active'", (gid,))]
        need = self._needed(p["mode"], len(snapshot), g["quorum"])
        self._x("""UPDATE proposals SET state='pending', snapshot=?, expires_at=?
                   WHERE id=?""",
                (json.dumps(snapshot), now + float(g["proposal_ttl"]), pid))
        self.audit(me, "group_consent", f"{pid} accepted, voting starts n={len(snapshot)}")
        self._recheck(gid, pid)
        st = self._q("SELECT state FROM proposals WHERE id=?", (pid,))[0]["state"]
        return {"proposal_id": pid, "state": st, "joined": st == "accepted",
                "mode": p["mode"], "needed": need, "voters": len(snapshot),
                "hint": "你已同意，现在进入群成员表决；表决通过后才真正入群。"}

    @staticmethod
    def _needed(mode: str, n: int, quorum: float = 0.0) -> int:
        if mode == "unan":
            return n
        if mode == "majority":
            import math
            base = math.floor(n / 2) + 1
            by_quorum = math.ceil(n * quorum) if quorum > 0 else 0
            return max(1, base, by_quorum)
        return 1

    def vote(self, me: str, gid: str, pid: str, vote: str) -> Dict[str, Any]:
        if vote not in ("yes", "no"):
            raise RegistryError("bad_request", "vote 只能是 yes/no")
        rows = self._q("SELECT * FROM proposals WHERE id=? AND group_id=?", (pid, gid))
        if not rows:
            raise RegistryError("not_found", "提案不存在", 404)
        p = rows[0]
        if p["state"] == CONSENT_PENDING:
            raise RegistryError("conflict", "受邀者尚未表态，表决还没开始", 409)
        if p["state"] != "pending":
            raise RegistryError("conflict", f"提案已 {p['state']}", 409)
        if time.time() > p["expires_at"]:
            self._resolve(gid, pid, "expired")
            raise RegistryError("expired", "提案已过期", 409)
        snapshot = json.loads(p["snapshot"])
        if me not in snapshot:
            raise RegistryError("forbidden", "你不在本提案的投票人快照中", 403)
        self._x("""INSERT INTO votes(proposal_id,agent_id,vote,created_at) VALUES (?,?,?,?)
                   ON CONFLICT(proposal_id,agent_id) DO UPDATE SET vote=?""",
                (pid, me, vote, time.time(), vote))
        g = self._q("SELECT * FROM groups WHERE id=?", (gid,))[0]
        vs = {r["agent_id"]: r["vote"] for r in self._q(
            "SELECT * FROM votes WHERE proposal_id=?", (pid,))}
        yes = sum(1 for v in vs.values() if v == "yes")
        no = sum(1 for v in vs.values() if v == "no")
        needed = self._needed(p["mode"], len(snapshot), g["quorum"])

        if p["mode"] == "unan":
            if no:
                self._resolve(gid, pid, "rejected")
            elif yes >= len(snapshot):
                self._resolve(gid, pid, "accepted")
        else:
            if yes >= needed:
                self._resolve(gid, pid, "accepted")
            elif no >= (len(snapshot) - needed + 1):
                self._resolve(gid, pid, "rejected")
        self.audit(me, "vote", f"{pid} {vote}")
        return {"proposal_id": pid, "yes": yes, "no": no, "needed": needed,
                "voters": len(snapshot),
                "state": self._q("SELECT state FROM proposals WHERE id=?", (pid,))[0]["state"]}

    def _resolve(self, gid: str, pid: str, state: str) -> None:
        p = self._q("SELECT * FROM proposals WHERE id=?", (pid,))[0]
        if p["state"] != "pending":
            return
        self._x("UPDATE proposals SET state=?, resolved_at=? WHERE id=?",
                (state, time.time(), pid))
        if state == "accepted" and p["kind"] == "invite":
            self._x("""INSERT INTO group_members(group_id,agent_id,role,state,joined_at)
                       VALUES (?,?,?,?,?) ON CONFLICT(group_id,agent_id)
                       DO UPDATE SET state='active'""",
                    (gid, p["target"], "member", "active", time.time()))

    def sweep_proposals(self) -> int:
        """清扫超时提案。由服务器后台线程周期性调用。

        两种超时要分开处理：等受邀者同意的邀请直接作废（expired_consent），
        已经进入表决的按群的 on_timeout 处理。
        """
        now = time.time()
        rows = self._q("""SELECT * FROM proposals
                          WHERE state IN ('pending', ?) AND expires_at<?""",
                       (CONSENT_PENDING, now))
        n = 0
        for p in rows:
            if p["state"] == CONSENT_PENDING:
                self._x("UPDATE proposals SET state='expired_consent', consent='expired' "
                        "WHERE id=?", (p["id"],))
                self.audit(None, "consent_expired", f"{p['group_id']} target={p['target']}")
                n += 1
                continue
            g = self._q("SELECT * FROM groups WHERE id=?", (p["group_id"],))
            if not g:
                continue
            if g[0]["on_timeout"] == "approve_if_quorum":
                vs = self._q("SELECT vote FROM votes WHERE proposal_id=?", (p["id"],))
                snapshot = json.loads(p["snapshot"])
                needed = self._needed(p["mode"], len(snapshot), g[0]["quorum"])
                yes = sum(1 for v in vs if v["vote"] == "yes")
                self._resolve(p["group_id"], p["id"], "accepted" if yes >= needed else "rejected")
            else:
                self._resolve(p["group_id"], p["id"], "expired")
            n += 1
        return n

    def _recheck(self, gid: str, pid: str) -> None:
        """成员变动后重算：避免"票已经够了，但没人再投"导致的永久挂起。"""
        rows = self._q("SELECT * FROM proposals WHERE id=? AND state='pending'", (pid,))
        if not rows:
            return
        p = rows[0]
        g = self._q("SELECT * FROM groups WHERE id=?", (gid,))
        if not g:
            return
        g = g[0]
        snapshot = json.loads(p["snapshot"])
        if not snapshot:
            return
        vs = {r["agent_id"]: r["vote"] for r in self._q(
            "SELECT * FROM votes WHERE proposal_id=?", (pid,))}
        yes = sum(1 for a in snapshot if vs.get(a) == "yes")
        no = sum(1 for a in snapshot if vs.get(a) == "no")
        needed = self._needed(p["mode"], len(snapshot), g["quorum"])
        if p["mode"] == "unan":
            if no:
                self._resolve(gid, pid, "rejected")
            elif yes >= len(snapshot):
                self._resolve(gid, pid, "accepted")
        else:
            if yes >= needed:
                self._resolve(gid, pid, "accepted")
            elif no >= max(1, len(snapshot) - needed + 1):
                self._resolve(gid, pid, "rejected")

    def remove_member(self, me: str, gid: str, target: str) -> Dict[str, Any]:
        g = self._q("SELECT * FROM groups WHERE id=?", (gid,))
        if not g:
            raise RegistryError("not_found", "群不存在", 404)
        g = g[0]
        m = self._member(gid, me)
        if not m:
            raise RegistryError("forbidden", "你不在这个群里", 403)
        if target != me and m["role"] not in ("owner", "admin"):
            raise RegistryError("forbidden", "只有管理员可以移除他人", 403)
        if target == g["owner"]:
            raise RegistryError("forbidden", "群主不能退出，请先转让", 403)
        self._x("DELETE FROM group_members WHERE group_id=? AND agent_id=?", (gid, target))
        # 关键：成员离开后，把他从未结提案的快照里剔除，否则表决永久挂起
        for p in self._q("SELECT * FROM proposals WHERE group_id=? AND state='pending'", (gid,)):
            snap = [a for a in json.loads(p["snapshot"]) if a != target]
            self._x("UPDATE proposals SET snapshot=? WHERE id=?",
                    (json.dumps(snap), p["id"]))
            self._recheck(gid, p["id"])
        self.audit(me, "group_remove", f"{gid} target={target}")
        return {"state": "removed"}

    def list_proposals(self, gid: str) -> List[Dict[str, Any]]:
        rows = self._q("""SELECT * FROM proposals WHERE group_id=?
                          ORDER BY created_at DESC LIMIT 100""", (gid,))
        out = []
        for r in rows:
            d = dict(r)
            d["snapshot"] = json.loads(d["snapshot"])
            d["votes"] = {v["agent_id"]: v["vote"] for v in self._q(
                "SELECT * FROM votes WHERE proposal_id=?", (r["id"],))}
            out.append(d)
        return out

    def pending_for(self, me: str) -> Dict[str, Any]:
        """我这边欠着的动作：待我表态的入群邀请 + 待我投的表决票。

        人和 Agent 共用同一份数据：人看可视化面板，Agent 拉这个接口。
        「有事没人通知我，于是整件事永久挂起」是这类系统的第一大死因。
        """
        invites: List[Dict[str, Any]] = []
        for r in self._q("""SELECT p.*, g.name AS group_name FROM proposals p
                            JOIN groups g ON g.id = p.group_id
                            WHERE p.target=? AND p.state=?
                            ORDER BY p.created_at DESC""", (me, CONSENT_PENDING)):
            d = dict(r)
            d["snapshot"] = []
            d["votes"] = {}
            invites.append(d)

        votes: List[Dict[str, Any]] = []
        for r in self._q("""SELECT p.*, g.name AS group_name FROM proposals p
                            JOIN groups g ON g.id = p.group_id
                            WHERE p.state='pending'
                            ORDER BY p.created_at DESC"""):
            snap = json.loads(r["snapshot"])
            if me not in snap:
                continue
            vs = {v["agent_id"]: v["vote"] for v in self._q(
                "SELECT * FROM votes WHERE proposal_id=?", (r["id"],))}
            if me in vs:
                continue
            d = dict(r)
            d["snapshot"] = snap
            d["votes"] = vs
            votes.append(d)
        return {"invites": invites, "votes": votes,
                "count": len(invites) + len(votes)}

    def silent_members(self, gid: str, days: float = 7.0) -> List[Dict[str, Any]]:
        """入群超过 N 天、却一条消息都没发过的成员。

        这是"长期静默收集"唯一能观测到的信号。它不是证据（有人就是只读），
        但它是一个值得人看一眼的名单——协议层面能做的到此为止，剩下的靠组织规矩。
        """
        now = time.time()
        out: List[Dict[str, Any]] = []
        for m in self.group_members(gid):
            if m["state"] != "active" or now - m["joined_at"] < days * 86400:
                continue
            c = self._q("""SELECT COUNT(*) c FROM messages
                           WHERE from_agent=? AND to_type='group' AND to_id=?""",
                        (m["agent_id"], gid))[0]["c"]
            if c == 0:
                out.append({**m, "days_in_group": round((now - m["joined_at"]) / 86400, 1)})
        return out

    def purge_old(self, days: float = 30.0) -> Dict[str, int]:
        """按留存策略清消息与投递记录。

        **审计表故意不在清理范围内**，这是刻意的，不是遗漏。
        业务数据有留存期（存着是隐私负担），审计记录是责任链（删了就没法追责）。
        两者共用同一个 cutoff 的话，谁都可以把 days 调成 0.01，
        于是"系统自动清理"就成了最省事的洗证据方式。
        审计要收缩，只能由人显式归档（`a2alink logs seal`），而归档动作本身也会留痕。
        """
        cutoff = time.time() - float(days) * 86400
        d1 = self._x("DELETE FROM deliveries WHERE created_at<?", (cutoff,)).rowcount or 0
        d2 = self._x("DELETE FROM messages WHERE created_at<?", (cutoff,)).rowcount or 0
        self.audit(None, "purge", f"days={days} msgs={d2} deliv={d1} audit=kept",
                   reason="server.purge",
                   extra={"days": days, "messages": d2, "deliveries": d1,
                          "audit_retained": True})
        return {"messages": d2, "deliveries": d1, "audit": 0}

    # ------------------------------------------------------------------
    # 数据面：消息准入 + 投递
    # ------------------------------------------------------------------
    def send(self, me: str, env: Envelope) -> Dict[str, Any]:
        if env.from_agent != me:
            raise RegistryError("forbidden", "信封 from 与登录身份不一致（疑似冒名）", 403)

        if env.to_type == "agent":
            if self._friend_state(me, env.to_id) != "accepted":
                raise RegistryError("not_friends",
                                    "不是好友，消息被拒。请先走双向好友审批流程。", 403)
            if not self._q("SELECT 1 FROM agents WHERE id=? AND status='active'", (env.to_id,)):
                raise RegistryError("not_found", "对端 Agent 不存在或已停用", 404)
            recipients = [env.to_id]
        else:
            m = self._member(env.to_id, me)
            if not m or m["state"] != "active":
                raise RegistryError("not_member", "你不在该群，无法发言", 403)
            recipients = [r["agent_id"] for r in self._q(
                """SELECT agent_id FROM group_members
                   WHERE group_id=? AND state='active' AND agent_id<>?""",
                (env.to_id, me))]

        now = time.time()
        with self.lock:
            if env.idempotency_key:
                ex = self._q("SELECT message_id FROM idem WHERE key=?", (env.idempotency_key,))
                if ex:
                    return {"duplicate": True, "message_id": ex[0]["message_id"],
                            "delivered_to": 0}
            cur = self._x("""INSERT INTO messages(id,from_agent,to_type,to_id,
                             conversation_id,envelope,created_at,trace_id)
                             VALUES (?,?,?,?,?,?,?,?)""",
                          (env.id, me, env.to_type, env.to_id,
                           env.conversation_id, env.to_json(), now,
                           env.trace_id or ""))
            mseq = cur.lastrowid
            for r in recipients:
                self._x("""INSERT INTO deliveries(message_seq,recipient,state,created_at)
                           VALUES (?,?,?,?)""", (mseq, r, "pending", now))
            if env.idempotency_key:
                self._x("INSERT OR IGNORE INTO idem(key,message_id,created_at) VALUES (?,?,?)",
                        (env.idempotency_key, env.id, now))
        self.audit(me, "send", f"conv={env.conversation_id} to={env.to_type}:{env.to_id} "
                               f"act={env.act} stage={env.stage} bytes={len(env.to_json())}",
                   trace=env.trace_id or "",
                   extra={"to": f"{env.to_type}:{env.to_id}", "act": env.act,
                          "stage": env.stage, "msg_id": env.id,
                          "recipients": len(recipients),
                          "bytes": len(env.to_json())})
        return {"message_id": env.id, "seq": mseq, "delivered_to": len(recipients),
                "duplicate": False}

    def inbox(self, me: str, cursor: int = 0, limit: int = 50,
              wait: float = 0.0) -> Dict[str, Any]:
        deadline = time.time() + max(0.0, min(30.0, wait))
        while True:
            rows = self._q("""SELECT d.seq, d.message_seq, m.envelope, m.from_agent, m.created_at
                              FROM deliveries d JOIN messages m ON m.seq=d.message_seq
                              WHERE d.recipient=? AND d.seq>?
                              ORDER BY d.seq LIMIT ?""", (me, cursor, max(1, min(200, limit))))
            if rows or time.time() >= deadline:
                break
            time.sleep(0.15)
        items = []
        for r in rows:
            try:
                env = json.loads(r["envelope"])
            except json.JSONDecodeError:
                continue
            env["_seq"] = r["seq"]
            items.append(env)
        return {"items": items, "cursor": rows[-1]["seq"] if rows else cursor,
                "count": len(items)}

    def ack(self, me: str, cursor: int) -> Dict[str, Any]:
        cur = self._x("UPDATE deliveries SET state='acked' WHERE recipient=? AND seq<=?"
                      " AND state='pending'", (me, cursor))
        return {"acked": cur.rowcount or 0, "cursor": cursor}

    def trace_view(self, trace: str, limit: int = 500) -> Dict[str, Any]:
        """按 trace_id 还原服务端这一侧的时间线。

        边界说明：注册中心只看得见自己经手的东西。
        客户端本地"为什么决定发这条"在各自 <home>/logs 里，不在这里——
        这是隐私边界，不是功能缺失。注册中心没有资格读参与方的本地日志。
        要全链路，用 `a2alink logs export` 从各端导出后合并。
        """
        rows = self._q("""SELECT seq,id,from_agent,to_type,to_id,conversation_id,
                                 created_at FROM messages WHERE trace_id=? ORDER BY seq""",
                       (trace,))
        dels = self._q("""SELECT d.message_seq,d.recipient,d.state,d.reason,m.from_agent
                          FROM deliveries d JOIN messages m ON m.seq=d.message_seq
                          WHERE m.trace_id=? ORDER BY d.seq""", (trace,))
        return {"trace": trace,
                "messages": [dict(r) for r in rows],
                "deliveries": [dict(r) for r in dels],
                "audit": self.audit_chain.read(limit=limit, trace=trace)}

    def audit_log(self, limit: int = 200) -> List[Dict[str, Any]]:
        rows = self._q("SELECT * FROM audit ORDER BY seq DESC LIMIT ?", (max(1, min(1000, limit)),))
        return [dict(r) for r in rows]

    def stats(self) -> Dict[str, Any]:
        def one(sql: str) -> int:
            r = self._q(sql)
            return r[0][0] if r else 0
        return {
            "agents": one("SELECT COUNT(*) FROM agents WHERE status='active'"),
            "friends_edges": one("SELECT COUNT(*) FROM friends WHERE state='accepted'"),
            "groups": one("SELECT COUNT(*) FROM groups"),
            "messages": one("SELECT COUNT(*) FROM messages"),
            "pending_proposals": one("SELECT COUNT(*) FROM proposals WHERE state='pending'"),
        }


# ==========================================================================
# HTTP 层（标准库，零依赖）
# ==========================================================================
class _Handler(BaseHTTPRequestHandler):
    server_version = "a2alink/0.1"
    registry: Registry  # 由工厂注入

    # ---- 工具 ----
    def log_message(self, fmt: str, *args: Any) -> None:
        if getattr(self.server, "verbose", False):  # type: ignore[attr-defined]
            super().log_message(fmt, *args)

    def _send(self, status: int, obj: Any) -> None:
        body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)

    def _err(self, status: int, code: str, message: str) -> None:
        self._send(status, {"error": {"code": code, "message": message}})

    def _body(self) -> Dict[str, Any]:
        try:
            n = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            n = 0
        if n > MAX_BODY:
            raise RegistryError("too_large", "请求体超过 1MB", 413)
        raw = self.rfile.read(n) if n else b""
        if not raw:
            return {}
        try:
            d = json.loads(raw.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError):
            raise RegistryError("bad_json", "请求体不是合法 JSON")
        if not isinstance(d, dict):
            raise RegistryError("bad_json", "请求体必须是 object")
        return d

    def _token(self) -> Optional[str]:
        h = self.headers.get("Authorization") or ""
        if h.lower().startswith("bearer "):
            return h[7:].strip()
        return None

    def _me(self) -> sqlite3.Row:
        row = self.registry.auth(self._token())
        self.actor_id = row["id"]        # 缓存，供拒绝留痕时定位"是谁被拒了"
        self.registry.rate_limit(row["id"])
        self.registry.touch(row["id"])
        return row

    def _actor(self) -> Optional[str]:
        """尽力解析调用者身份，失败返回 None（未认证请求也要留痕）。"""
        aid = getattr(self, "actor_id", None)
        if aid:
            return aid
        try:
            self.actor_id = self.registry.auth(self._token())["id"]
            return self.actor_id
        except Exception:
            return None

    def _reject(self, status: int, code: str, message: str, route: str) -> None:
        """每一次拒绝都留痕。

        为什么单独做这一步：服务端原来只记"成功做了什么"，
        被拒的请求一拍两散。于是"我明明被拦了"和"根本没这回事"
        两种说法谁也证不了。拒绝记录里带 status + code + 路由 + 调用者，
        足以还原"谁在什么时候想做什么、被什么理由挡了"。
        """
        try:
            self.registry.audit(self._actor(), "reject", f"{code} {route}", decision="deny",
                                reason="server.reject",
                                extra={"status": status, "code": code,
                                       "route": route, "msg": message})
        except Exception:
            pass    # 审计失败不能把 4xx 变成 5xx，那会让问题更难查

    # ---- 路由 ----
    ROUTES: List[Tuple[str, str, str]] = [
        ("GET", r"^/healthz$", "h_health"),
        ("GET", r"^/v1/stats$", "h_stats"),
        ("POST", r"^/v1/agents/register$", "h_register"),
        ("GET", r"^/v1/agents$", "h_discover"),
        ("GET", r"^/v1/agents/(?P<aid>[A-Za-z0-9\-_]+)$", "h_agent"),
        ("POST", r"^/v1/friends/requests$", "h_friend_req"),
        ("GET", r"^/v1/friends/requests$", "h_friend_reqs"),
        ("POST", r"^/v1/friends/requests/(?P<rid>[A-Za-z0-9\-_]+)/respond$", "h_friend_respond"),
        ("GET", r"^/v1/friends$", "h_friends"),
        ("DELETE", r"^/v1/friends/(?P<aid>[A-Za-z0-9\-_]+)$", "h_unfriend"),
        ("POST", r"^/v1/groups$", "h_group_create"),
        ("GET", r"^/v1/groups/(?P<gid>[A-Za-z0-9\-_]+)$", "h_group_info"),
        ("POST", r"^/v1/groups/(?P<gid>[A-Za-z0-9\-_]+)/invite$", "h_group_invite"),
        ("POST", r"^/v1/groups/(?P<gid>[A-Za-z0-9\-_]+)/vote$", "h_group_vote"),
        ("POST", r"^/v1/groups/(?P<gid>[A-Za-z0-9\-_]+)/consent$", "h_group_consent"),
        ("GET", r"^/v1/groups/(?P<gid>[A-Za-z0-9\-_]+)/privacy$", "h_group_privacy"),
        ("GET", r"^/v1/groups/(?P<gid>[A-Za-z0-9\-_]+)/proposals$", "h_group_props"),
        ("POST", r"^/v1/groups/(?P<gid>[A-Za-z0-9\-_]+)/remove$", "h_group_remove"),
        ("GET", r"^/v1/pending$", "h_pending"),
        ("POST", r"^/v1/messages$", "h_send"),
        ("GET", r"^/v1/inbox$", "h_inbox"),
        ("POST", r"^/v1/inbox/ack$", "h_ack"),
        ("GET", r"^/v1/audit$", "h_audit"),
        ("GET", r"^/v1/trace/(?P<tid>[A-Za-z0-9\-_]+)$", "h_trace"),
    ]

    def do_GET(self) -> None:  # noqa: N802
        self._dispatch("GET")

    def do_POST(self) -> None:  # noqa: N802
        self._dispatch("POST")

    def do_DELETE(self) -> None:  # noqa: N802
        self._dispatch("DELETE")

    def _dispatch(self, method: str) -> None:
        parsed = urlparse(self.path)
        route = f"{method} {parsed.path}"
        try:
            for m, pat, fn in self.ROUTES:
                if m != method:
                    continue
                mt = re.match(pat, parsed.path)
                if mt:
                    args = {k: v for k, v in mt.groupdict().items()}
                    qs = {k: v[0] for k, v in parse_qs(parsed.query).items()}
                    getattr(self, fn)(args, qs)
                    return
            self._reject(404, "no_route", f"未知路由 {route}", route)
            self._err(404, "no_route", f"未知路由 {method} {parsed.path}")
        except RegistryError as e:
            self._reject(e.status, e.code, e.message, route)
            self._err(e.status, e.code, e.message)
        except ProtocolError as e:
            self._reject(400, "bad_envelope", str(e), route)
            self._err(400, "bad_envelope", str(e))
        except BrokenPipeError:
            pass
        except Exception as e:  # pragma: no cover - 兜底
            self._reject(500, "internal", f"{type(e).__name__}: {e}", route)
            self._err(500, "internal", f"{type(e).__name__}: {e}")

    # ---- handlers ----
    def h_health(self, a: Dict[str, str], q: Dict[str, str]) -> None:
        self._send(200, {"ok": True, "service": "a2alink", "ts": time.time()})

    def h_stats(self, a, q) -> None:
        self._send(200, self.registry.stats())

    def h_register(self, a, q) -> None:
        d = self._body()
        out = self.registry.register(
            name=str(d.get("name", "")),
            capabilities=list(d.get("capabilities") or []),
            owner=str(d.get("owner", ""))[:120],
            description=str(d.get("description", ""))[:500],
            endpoint=str(d.get("endpoint", ""))[:300],
            invite_code=d.get("invite_code"))
        self._send(201, out)

    def h_discover(self, a, q) -> None:
        self._send(200, {"agents": self.registry.discover(
            q.get("capability"), q.get("q"), int(q.get("limit", 50) or 50))})

    def h_agent(self, a, q) -> None:
        rows = self.registry._q("SELECT * FROM agents WHERE id=?", (a["aid"],))
        if not rows:
            self._err(404, "not_found", "Agent 不存在")
            return
        self._send(200, self.registry.public_agent(rows[0]))

    def h_friend_req(self, a, q) -> None:
        me = self._me()
        d = self._body()
        self._send(201, self.registry.friend_request(
            me["id"], str(d.get("to", "")), str(d.get("message", ""))))

    def h_friend_reqs(self, a, q) -> None:
        me = self._me()
        self._send(200, {"requests": self.registry.friend_requests(me["id"], q.get("box", "in"))})

    def h_friend_respond(self, a, q) -> None:
        me = self._me()
        d = self._body()
        self._send(200, self.registry.friend_respond(me["id"], a["rid"], bool(d.get("accept"))))

    def h_friends(self, a, q) -> None:
        me = self._me()
        self._send(200, {"friends": self.registry.friends(me["id"])})

    def h_unfriend(self, a, q) -> None:
        me = self._me()
        self._send(200, self.registry.unfriend(me["id"], a["aid"]))

    def h_group_create(self, a, q) -> None:
        me = self._me()
        d = self._body()
        self._send(201, self.registry.create_group(
            me["id"], str(d.get("name", "")), str(d.get("join_mode", "unan")),
            float(d.get("quorum", 0) or 0), float(d.get("proposal_ttl", 86400) or 86400),
            int(d.get("max_members", 50) or 50), str(d.get("on_timeout", "reject")),
            bool(d.get("trusted_direct", True)),
            float(d.get("consent_ttl", CONSENT_TTL) or CONSENT_TTL),
            int(d.get("invite_per_hour", 20) or 20)))

    def h_group_info(self, a, q) -> None:
        me = self._me()
        g = self.registry.group_info(a["gid"])
        if any(m["agent_id"] == me["id"] and m["state"] == "active" for m in g["members"]):
            self._send(200, g)
            return
        # 被邀请但还没入群的人，只能看最小信息集（无成员名单）
        if self.registry.invitee(a["gid"], me["id"]):
            self._send(200, self.registry.group_public_info(a["gid"]))
            return
        self._err(403, "forbidden", "你不在这个群里")

    def h_group_invite(self, a, q) -> None:
        me = self._me()
        d = self._body()
        self._send(201, self.registry.invite(me["id"], a["gid"], str(d.get("agent_id", ""))))

    def h_group_consent(self, a, q) -> None:
        me = self._me()
        d = self._body()
        accept = d.get("accept")
        if not isinstance(accept, bool):
            self._err(400, "bad_request", "accept 必须是布尔值（true/false），不接受 'yes'/1")
            return
        self._send(200, self.registry.consent(
            me["id"], a["gid"], str(d.get("proposal_id", "")), accept,
            str(d.get("reason", ""))))

    def h_pending(self, a, q) -> None:
        me = self._me()
        self._send(200, self.registry.pending_for(me["id"]))

    def h_group_privacy(self, a, q) -> None:
        me = self._me()
        g = self.registry.group_info(a["gid"])
        if not any(m["agent_id"] == me["id"] and m["state"] == "active" for m in g["members"]):
            self._err(403, "forbidden", "你不在这个群里")
            return
        self._send(200, {"silent_members": self.registry.silent_members(
            a["gid"], float(q.get("days", 7) or 7))})

    def h_group_vote(self, a, q) -> None:
        me = self._me()
        d = self._body()
        self._send(200, self.registry.vote(me["id"], a["gid"],
                                           str(d.get("proposal_id", "")), str(d.get("vote", ""))))

    def h_group_props(self, a, q) -> None:
        me = self._me()
        # 非成员不能看提案流水：里面有"谁在拉谁进群"，是最典型的侦察素材。
        m = self.registry._member(a["gid"], me["id"])
        if not m or m["state"] != "active":
            self._err(403, "forbidden", "你不在这个群里")
            return
        self._send(200, {"proposals": self.registry.list_proposals(a["gid"])})

    def h_group_remove(self, a, q) -> None:
        me = self._me()
        d = self._body()
        self._send(200, self.registry.remove_member(me["id"], a["gid"], str(d.get("agent_id", ""))))

    def h_send(self, a, q) -> None:
        me = self._me()
        d = self._body()
        env = Envelope.from_dict(d.get("envelope"))
        self._send(202, self.registry.send(me["id"], env))

    def h_inbox(self, a, q) -> None:
        me = self._me()
        self._send(200, self.registry.inbox(
            me["id"], int(q.get("cursor", 0) or 0), int(q.get("limit", 50) or 50),
            float(q.get("wait", 0) or 0)))

    def h_ack(self, a, q) -> None:
        me = self._me()
        d = self._body()
        self._send(200, self.registry.ack(me["id"], int(d.get("cursor", 0) or 0)))

    def h_audit(self, a, q) -> None:
        self._send(200, {"audit": self.registry.audit_log(int(q.get("limit", 200) or 200))})

    def h_trace(self, a, q) -> None:
        """按 trace 查服务端时间线。只有参与方有权查——排查不等于可以随便翻别人。"""
        me = self._me()
        tid = a["tid"]
        d = self.registry.trace_view(tid, int(q.get("limit", 500) or 500))
        involved = any(m["from_agent"] == me["id"] for m in d["messages"]) or \
            any(x["recipient"] == me["id"] for x in d["deliveries"])
        if not involved:
            self._err(403, "forbidden", "你不是这条 trace 的参与方，无权查看")
            return
        # 只回元数据，不回 payload —— 查问题不需要把别人的正文再复制一遍。
        self._send(200, {"trace": tid,
                         "messages": d["messages"],
                         "my_deliveries": [x for x in d["deliveries"]
                                           if x["recipient"] == me["id"]],
                         "audit": [e for e in d["audit"]
                                   if e.get("actor") in (f"agent:{me['id']}",
                                                         "service:registry")]})


def make_server(registry: Registry, host: str = "127.0.0.1", port: int = 8787,
                verbose: bool = False) -> ThreadingHTTPServer:
    handler = type("BoundHandler", (_Handler,), {"registry": registry})
    srv = ThreadingHTTPServer((host, port), handler)
    srv.daemon_threads = True
    srv.verbose = verbose       # type: ignore[attr-defined]
    return srv


def serve(registry: Registry, host: str = "127.0.0.1", port: int = 8787,
          verbose: bool = False, block: bool = True,
          sweep_interval: float = 30.0) -> ThreadingHTTPServer:
    srv = make_server(registry, host, port, verbose)

    def _sweeper() -> None:
        while True:
            time.sleep(sweep_interval)
            try:
                registry.sweep_proposals()
            except Exception:
                pass

    if block:
        threading.Thread(target=_sweeper, daemon=True).start()
        print(f"[a2alink] 注册中心已启动: http://{host}:{port}  db={registry.db_path}")
        if host not in ("127.0.0.1", "localhost", "::1"):
            print("[a2alink] ⚠️ 当前监听在非回环地址：任何能访问该端口的人都能注册/发消息。"
                  "\n          公网部署前必须：1) 设置 --invite-code 2) 前置 TLS 反代 "
                  "3) 关闭 open 注册 4) 阅读 SECURITY.md")
        try:
            srv.serve_forever()
        except KeyboardInterrupt:
            print("\n[a2alink] 正在停止…")
    return srv
