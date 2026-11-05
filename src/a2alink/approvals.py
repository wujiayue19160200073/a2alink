"""待发内容的审批队列：把"被拦下的消息"从死路变成一道选择题。

## 为什么需要它

出站 DLP 判 BLOCK 时直接丢弃，看起来最安全，实际会把人逼到一条更差的路：
"先改成能过闸门的样子，再发"。那不是安全，那是绕过——而且绕过之后
审计链上留下的是一条干净的"allow"。

所以正确做法不是"拦死"，而是**停下来把要发什么摆到人面前**，让人决定：

    有机密 → 挂起 → 人看一眼 → 批准（留理由）或 拒绝

这也正是使用者提的诉求：有机密信息要问，而不是直接拒。

## 为什么挂起的内容要加密

挂起的是**还没发出去的内容**，其中往往正好包含敏感信息——这是它被拦的原因。
把这样的内容明文写在磁盘上，等于在本地开了第二个泄露口，而这个口子
通常没人会去管（谁会想到 `~/.a2alink/approvals/` 里躺着一堆连接串）。

做法：用一把本机主密钥做 AEAD，密文落盘。密钥文件 `0600`。

## 边界（写清楚，不含糊）

1. **密钥与密文同在 `~/.a2alink/` 下**。同机的 root、同 OS 用户都能同时读到
   两者，所以能解开。它挡的是：误上传、误备份、同事翻文件、顺手 `grep`。
   **它不挡 root，也不挡拿到你整个 home 目录的人。** 和审计链是同一条边界。
2. **这不是人机隔离**。Agent 同样能执行 `approve` 命令——它和你在同一个
   shell 里，技术上无法区分。能做的只有两件事：把每次批准写成带责任人的
   审计记录；在非交互环境里要求显式 `--yes` 加理由，让"静默自动批准"
   不可能发生而不留痕。
3. **审批不等于审查内容质量**。它只回答"这段内容允许出域吗"，
   不回答"这段内容对不对"。后者是人的事。
"""

from __future__ import annotations

import json
import os
import re
import time
from typing import Any, Dict, List, Optional, Tuple

from .crypto import CryptoError, DecryptionError, aead_open, aead_seal, random_bytes
from .protocol import new_id

# 审批件的存活时间。过了就清掉加密内容——挂起的内容不该永久留在磁盘上，
# 否则它会变成一个没人清理的"历史机密归档"，那比不挂起更糟。
DEFAULT_TTL = 24 * 3600

PID_RE = re.compile(r"apv-[0-9a-f]{24}")

# 状态机。注意 sent 是终态：批准之后是否真的发出去了，由调用方回填。
# 把它和 approved 分开，是因为"批准了但发送失败"必须看得出来，
# 否则人以为发出去了，对方永远收不到。
ST_PENDING = "pending"
ST_APPROVED = "approved"
ST_SENT = "sent"
ST_DENIED = "denied"
ST_EXPIRED = "expired"

STATUSES = (ST_PENDING, ST_APPROVED, ST_SENT, ST_DENIED, ST_EXPIRED)


class ApprovalError(ValueError):
    """审批件相关的人为错误，消息面向使用者。"""


def _default_root() -> str:
    return os.environ.get("A2ALINK_HOME") or os.path.join(
        os.path.expanduser("~"), ".a2alink")


class ApprovalStore:
    """一个目录、一把密钥、一堆 JSON。

    不用数据库：审批件的生命周期很短（几小时），量也小（人手批准的节奏），
    而 SQLite 会让"看一眼这个文件里有什么"变得需要工具。排查时能直接
    `cat` 出来的东西更容易被信任。
    """

    def __init__(self, root: Optional[str] = None,
                 key_path: Optional[str] = None,
                 ttl: int = DEFAULT_TTL) -> None:
        base = root or _default_root()
        self.dir = os.path.join(base, "approvals")
        self.key_path = key_path or os.path.join(base, "approvals.key")
        self.ttl = max(60, int(ttl))

    # ------------------------------------------------------------------ 密钥
    def _key(self, create: bool = True) -> bytes:
        """读主密钥；不存在则生成。

        ``create=False`` 用于只读场景（列表、统计）：只是看一眼队列，
        不该顺手在磁盘上造出一把新密钥——万一原密钥被误删，静默新建
        会让所有既有审批件变得永远解不开，而症状是"突然全解不开了"。
        """
        try:
            with open(self.key_path, "rb") as f:
                k = f.read()
            if len(k) == 32:
                return k
            # 长度不对说明文件被改坏了。这时**不能**悄悄覆盖——覆盖等于
            # 把已有审批件永久毁掉。宁可报错让人把文件恢复或清空重来。
            raise ApprovalError(
                f"主密钥文件 {self.key_path} 长度异常（{len(k)} 字节），"
                f"应为 32。为免毁掉已有审批件，不做自动修复。")
        except FileNotFoundError:
            if not create:
                return b""
        if not create:
            return b""
        os.makedirs(os.path.dirname(self.key_path) or ".", exist_ok=True)
        k = random_bytes(32)
        # O_EXCL：并发首次启动时两边都生成密钥的后果是有一半审批件解不开。
        try:
            fd = os.open(self.key_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL
                         | (getattr(os, "O_BINARY", 0)), 0o600)
        except FileExistsError:
            with open(self.key_path, "rb") as f:
                return f.read()
        try:
            os.write(fd, k)
        finally:
            os.close(fd)
        # 显式再 chmod 一次：POSIX 上 os.open 的 mode 会受 umask 影响
        # （umask 022 时 0600 仍是 0600，这里主要是兜底）；
        # Windows 上文件权限模型不同，chmod 只会影响只读位，写不进 ACL——
        # 所以 Windows 上"只有我能读"靠的是用户目录本身的 ACL，
        # 这一点在 docs 里写明，不要让人误以为 0600 在 Windows 上等价。
        try:
            os.chmod(self.key_path, 0o600)
        except OSError:
            pass
        return k

    # ------------------------------------------------------------------ 存取
    def _path(self, pid: str) -> str:
        if not PID_RE.fullmatch(pid or ""):
            raise ApprovalError(f"审批件 ID 非法: {pid!r}")
        return os.path.join(self.dir, f"{pid}.json")

    def _write(self, rec: Dict[str, Any]) -> None:
        os.makedirs(self.dir, exist_ok=True)
        p = self._path(rec["id"])
        tmp = p + f".tmp{os.getpid()}"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(rec, f, ensure_ascii=False, indent=1, sort_keys=True)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, p)
        try:
            os.chmod(p, 0o600)
        except OSError:
            pass

    def _read_raw(self, pid: str) -> Dict[str, Any]:
        try:
            with open(self._path(pid), "r", encoding="utf-8") as f:
                d = json.load(f)
        except FileNotFoundError:
            raise ApprovalError(f"没有这个审批件: {pid}")
        except (OSError, ValueError) as e:
            raise ApprovalError(f"审批件 {pid} 读不出来（文件损坏？）: {e}")
        d.setdefault("status", ST_PENDING)
        d.setdefault("sealed", {})
        return d

    # ------------------------------------------------------------------ 挂起
    def hold(self, *, requester: str, session: str, peer: str, scope: str,
             act: str, stage: str, payload: Dict[str, Any],
             findings: List[Dict[str, Any]], level: str, trace: str = "",
             replay: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """把一条被拦下的消息存起来，返回可展示的记录（**不含内容**）。

        返回的记录里刻意没有正文，连预览都没有。理由：预览同样是原文，
        把它写进"可展示的元数据"等于换个字段名继续泄露。人要看内容时
        走 ``preview()``，它解密后只打印给当前终端，不落盘。
        """
        pid = new_id("apv-")
        now = time.time()
        body = json.dumps(payload, ensure_ascii=False, sort_keys=True).encode("utf-8")
        key = self._key()
        # AAD 绑定审批件 ID：把 A 的内容塞进 B 的记录里，tag 就验不过。
        sealed = aead_seal(key, body, aad=pid.encode("ascii"))
        rec: Dict[str, Any] = {
            "id": pid,
            "created_at": now,
            "expires_at": now + self.ttl,
            "status": ST_PENDING,
            "requester": str(requester)[:80],
            "session": str(session)[:80],
            "peer": str(peer)[:80],
            "scope": str(scope)[:16],
            "act": str(act)[:24],
            "stage": str(stage)[:24],
            "level": str(level)[:24],
            "rules": sorted({str(f.get("rule", "")) for f in findings})[:16],
            "findings": len(findings),
            "bytes": len(body),
            "trace": str(trace)[:80],
            # 重放需要的上下文（不含正文）。缺哪项就用默认值，不要凭空补。
            "replay": {k: v for k, v in dict(replay or {}).items()
                       if k in ("ttl_seconds", "ttl_hops", "conversation_id",
                                "in_reply_to", "max_messages", "max_tokens")},
            "sealed": sealed,
            "decided_at": None,
            "decided_by": "",
            "reason": "",
        }
        self._write(rec)
        return self.public_view(rec)

    # ------------------------------------------------------------------ 读取
    @staticmethod
    def public_view(rec: Dict[str, Any]) -> Dict[str, Any]:
        """对外展示的字段。sealed 绝不出现——它是密文，给了也没用，
        但它会让人误以为"内容在这"，从而去试。"""
        return {k: v for k, v in rec.items() if k != "sealed"}

    def preview(self, pid: str, limit: int = 2000) -> Tuple[Dict[str, Any], str]:
        """解密并返回正文（给人看）。只在终端里打印，不写回文件。"""
        rec = self._read_raw(pid)
        if not rec.get("sealed"):
            st = rec.get("status")
            why = {ST_DENIED: "已被拒绝，内容当时就销毁了",
                   ST_SENT: "已发出，内容已随发送清理",
                   ST_EXPIRED: "已过期，内容已销毁"}.get(
                       st, "没有可解密的内容")
            raise ApprovalError(f"{pid} {why}。")
        try:
            raw = aead_open(self._key(create=False), rec["sealed"],
                            aad=pid.encode("ascii"))
        except DecryptionError as e:
            raise ApprovalError(
                f"{pid} 解不开：{e}。通常是主密钥文件被换过或删过。")
        try:
            text = json.loads(raw.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            text = {"_raw": raw.decode("utf-8", "replace")}
        body = json.dumps(text, ensure_ascii=False, indent=2)
        return self.public_view(rec), body[:max(200, int(limit))]

    def list(self, status: Optional[str] = None,
             limit: int = 100) -> List[Dict[str, Any]]:
        """列出审批件。默认按时间倒序。"""
        if status is not None and status not in STATUSES:
            raise ApprovalError(f"未知状态 {status!r}，可选：{'/'.join(STATUSES)}")
        if not os.path.isdir(self.dir):
            return []
        out: List[Dict[str, Any]] = []
        for name in os.listdir(self.dir):
            if not name.endswith(".json"):
                continue
            pid = name[:-5]
            if not PID_RE.fullmatch(pid):
                continue
            try:
                rec = self._read_raw(pid)
            except ApprovalError:
                continue
            if status and rec.get("status") != status:
                continue
            out.append(self.public_view(rec))
        out.sort(key=lambda r: float(r.get("created_at") or 0), reverse=True)
        return out[:max(1, int(limit))]

    def get(self, pid: str) -> Dict[str, Any]:
        return self.public_view(self._read_raw(pid))

    # ------------------------------------------------------------------ 决定
    def _decide(self, pid: str, status: str, by: str, reason: str,
                drop_body: bool = False) -> Dict[str, Any]:
        rec = self._read_raw(pid)
        self._require_pending(rec)
        rec["status"] = status
        rec["decided_at"] = time.time()
        rec["decided_by"] = str(by)[:80]
        rec["reason"] = str(reason)[:200]
        if drop_body:
            rec["sealed"] = {}
            rec["bytes"] = 0
        self._write(rec)
        return self.public_view(rec)

    def _require_pending(self, rec: Dict[str, Any]) -> None:
        """状态检查必须排在解密之前。

        顺序反了会让"重复批准"报成"内容解不开"——那会让人以为密钥坏了，
        跑去恢复密钥，而真实原因只是这条已经批过了。错误的错误信息
        比没有错误信息更费时间。
        """
        st = rec.get("status")
        if st != ST_PENDING:
            extra = ""
            if st == ST_SENT:
                extra = "（已经发出去了，不用再批）"
            elif st == ST_DENIED:
                extra = "（已被拒绝，内容已销毁）"
            elif st == ST_EXPIRED:
                extra = "（已过期，内容已销毁）"
            raise ApprovalError(
                f"{rec.get('id')} 当前状态是 {st}{extra}，不能再次决定。"
                f"上次决定：{rec.get('decided_by') or '未知'}"
                f" / {rec.get('reason') or '无理由'}")
        if self._expired(rec):
            raise ApprovalError(
                f"{rec.get('id')} 已过期（超过 {self.ttl} 秒没处理），内容已不可用。"
                f"请重新发一次原始请求。")

    def approve(self, pid: str, by: str, reason: str) -> Tuple[Dict[str, Any], Dict[str, Any]]:
        """批准。返回 ``(记录, 可重放的内容)``。

        解密放在这里、返回给调用方，而不是让调用方自己拿 sealed 去解：
        解密的时机越少越好，早解一次就多一份留在内存里的时间。
        """
        if len(str(reason).strip()) < 4:
            raise ApprovalError("批准必须写理由（至少 4 个字）。"
                                "这不是形式主义——事后追责时它是唯一能说清'为什么放行'的东西。")
        rec = self._read_raw(pid)
        self._require_pending(rec)
        if not rec.get("sealed"):
            raise ApprovalError(f"{pid} 没有可解密的内容，无法重放")
        try:
            raw = aead_open(self._key(create=False), rec["sealed"],
                            aad=pid.encode("ascii"))
            payload = json.loads(raw.decode("utf-8"))
        except (DecryptionError, ValueError) as e:
            raise ApprovalError(f"{pid} 批准失败：内容解不开（{e}）")
        view = self._decide(pid, ST_APPROVED, by, reason)
        return view, payload

    def deny(self, pid: str, by: str, reason: str) -> Dict[str, Any]:
        """拒绝。**同时销毁内容**——被拒绝的东西没有继续留在磁盘上的理由，
        留着只是多一个泄露面。"""
        return self._decide(pid, ST_DENIED, by, reason, drop_body=True)

    def mark_sent(self, pid: str, message_id: str = "") -> Dict[str, Any]:
        """回填"已发出"。批准和发出是两件事，不能合并：

        批准后发送可能失败（网络、对端不存在）。合并的话，失败会表现为
        "已批准"——而人看到"已批准"就以为事情结束了，不会再去查。
        """
        rec = self._read_raw(pid)
        if rec.get("status") not in (ST_APPROVED, ST_SENT):
            raise ApprovalError(
                f"{pid} 当前是 {rec.get('status')}，只有已批准的才能标记已发")
        rec["status"] = ST_SENT
        rec["message_id"] = str(message_id)[:80]
        rec["sent_at"] = time.time()
        rec["sealed"] = {}
        rec["bytes"] = 0
        self._write(rec)
        return self.public_view(rec)

    # ------------------------------------------------------------------ 维护
    @staticmethod
    def _expired(rec: Dict[str, Any], now: Optional[float] = None) -> bool:
        return float(rec.get("expires_at") or 0) < (now if now is not None else time.time())

    def purge_expired(self, now: Optional[float] = None) -> int:
        """把过期的 pending 标成 expired 并销毁内容。返回处理条数。

        注意是**标记 + 销毁内容**，不是删文件：删掉的话"曾经有个东西
        挂在这里但没人管"这件事就查不到了，而那恰恰是最该被看见的
        ——它说明流程里有人在等一个人做决定，而那个人没出现。
        """
        n = 0
        for rec in self.list(status=ST_PENDING, limit=10000):
            raw = self._read_raw(rec["id"])
            if not self._expired(raw, now):
                continue
            raw["status"] = ST_EXPIRED
            raw["sealed"] = {}
            raw["bytes"] = 0
            raw["decided_at"] = None
            self._write(raw)
            n += 1
        return n

    def stats(self) -> Dict[str, Any]:
        counts = {s: 0 for s in STATUSES}
        oldest = None
        for rec in self.list(limit=10000):
            counts[rec.get("status", ST_PENDING)] = counts.get(
                rec.get("status", ST_PENDING), 0) + 1
            if rec.get("status") == ST_PENDING:
                t = float(rec.get("created_at") or 0)
                oldest = t if oldest is None else min(oldest, t)
        return {"counts": counts, "oldest_pending": oldest,
                "pending": counts.get(ST_PENDING, 0)}
