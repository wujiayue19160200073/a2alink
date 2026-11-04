"""审计日志：让每一条"放行/拦截"都能被追到人。

======================= 为什么需要这个模块 =======================
出事之后，最没用的三句话是：
    "我记得我没让它发。"
    "日志里没记录，应该没发生过。"
    "可能是对方那边的问题。"

要堵住这三句，日志必须同时满足四条硬要求：

1) **默认记录，不记也留痕**
   不只是"拦截了"要记，"检查通过"也要记。因为事后要证明的往往不是
   "我拦了"，而是"我检查过、当时按什么规则判的"。缺了这一半，
   一次合规审计里你无法自证清白。

2) **决策必须有机器可读的理由码（reason code）**
   自由文本是甩锅的温床。"已处理""异常"这种日志等于没写。
   本模块把所有裁决收敛成枚举，写错一个字都会报错。

3) **区分谁做的决定**
   agent 自己决定 / 人明确确认 / 系统自动。三者责任完全不同。
   人工强行放行（override）必须带理由，且长度有下限——
   就是为了让"我随手点了下"这种话写不上去。

4) **不可悄悄改写**
   每条记录做哈希链：h = sha256(prev + 本条规范化内容)。
   改一条、删中间一条、调换顺序，链就断。再配一个独立于日志文件的
   HEAD 锚点，删掉尾部也能被发现。

====================== 必须说清楚的局限 ======================
这是**本地**哈希链，它防的是"事后偷偷改一行"，防不了"拿到 root 之后
把日志和 HEAD 一起重写"。真要不可否认，必须把 HEAD 定期锚定到
你自己控制之外的地方（另一台机器 / SIEM / 可信时间戳服务）。
本模块提供 anchor_hook 口子，但不假装本地链等于不可否认。

另一个必须说清的：**日志本身是泄密面**。
所以本模块默认只存指纹（sha256）、长度、命中规则名和极短预览，
绝不存 payload 原文。预览长度默认 48 字符，设 0 可完全关闭。
把日志当证据的前提，是它自己不能变成第二份敏感数据副本。
"""

from __future__ import annotations

import atexit
import hashlib
import json
import os
import re
import time
from datetime import datetime, timezone, timedelta
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple

# 日志格式版本。字段结构变了就升版本，便于老日志仍可解析。
LOG_SCHEMA = 1

# 规范化 JSON 序列化参数：排序 + 无多余空格，保证同样内容算出同样哈希。
_CANON = dict(sort_keys=True, ensure_ascii=False, separators=(",", ":"))

CST = timezone(timedelta(hours=8))


# ----------------------------------------------------------------------
# 理由码：全部枚举，禁止自由文本
# ----------------------------------------------------------------------
# 命名规则：<子系统>.<结果>。结果只有五种：
#   allow 放行 / redact 脱敏后放行 / deny 拒绝 / drop 丢弃 / note 仅记录
REASONS: Dict[str, str] = {
    # —— 出站 DLP ——
    "egress.allow": "出站内容通过敏感信息检查，无命中",
    "egress.redact": "出站内容命中可脱敏项，已替换后放行",
    "egress.deny": "出站内容命中禁止出域项，已阻断",
    "egress.override": "出站内容被拦，但由人确认后强行放行",

    # —— 看门狗（循环治理）——
    "watchdog.allow": "预算与指纹检查通过",
    "watchdog.degrade": "接近配额上限，降级为只读/不追问",
    "watchdog.deny": "触发熔断：配额、预算、TTL 或内容指纹重复",
    "watchdog.override": "看门狗已熔断，但由人确认后强行放行",

    # —— 反扩散 ——
    "propagation.allow": "扩散检查通过",
    "propagation.deny_fanout": "同一内容短时发往过多目标，判定为扩散行为",
    "propagation.deny_forward": "转发功能未开启，拒绝代他人传话",
    "propagation.override": "扩散检查已命中，但由人确认后强行放行",

    # —— 线缆（真正进出网络的动作）——
    "wire.sent": "信封已提交注册中心",
    "wire.send_failed": "信封提交失败（网络或服务端拒绝）",
    "wire.received": "从收件箱取到信封",
    "wire.duplicate": "幂等键命中，服务端判定为重复投递",
    "wire.dropped_malformed": "信封格式非法，直接丢弃，未进入上下文",
    "wire.dropped_not_friend": "非好友消息被服务端拒绝（不应出现在客户端，出现即为异常）",
    "wire.bad_signature": "入站信封签名校验失败，已拒收（内容被改或发送者身份不符）",

    # —— 入站围栏 ——
    "ingress.allow": "入站内容未检出注入特征，已加围栏标记后放行",
    "ingress.quarantine": "入站内容检出提示词注入特征，已隔离不进入上下文",

    # —— 密码学（v0.2 公钥体系）——
    "crypto.sealed": "出站信封已用对端交换公钥端到端加密，并已签名",
    "crypto.plaintext": "出站信封未加密，仅签名（单聊但拿不到对端公钥）",
    "crypto.group_plaintext": "群消息仅签名不加密（服务端 fan-out，v0.2 限制）",
    "crypto.opened": "入站信封解密成功，签名此前已验证",
    "crypto.decrypt_failed": "入站信封解密失败，已拒收（密钥不对或密文被篡改）",
    "crypto.plaintext_inbound": "收到未加密的入站信封（对端可能未登记公钥）",
    "crypto.signature_skipped": "按配置跳过了签名校验（高风险降级，需人工确认）",
    "crypto.pin_new": "首次见到对端公钥并自动记录（TOFU，指纹未经带外核对）",
    "crypto.pin_match": "对端公钥与本地固定值一致",
    "crypto.key_changed": "对端公钥与本地固定值不一致，已拒收（可能是换钥匙或冒充）",
    "crypto.key_rotated": "本机轮换了密钥对，旧私钥已归档",
    "crypto.keys_published": "本机公钥已登记到注册中心",

    # —— 生命周期 ——
    "agent.boot": "客户端启动，审计链已接续",
    "agent.exit": "客户端退出，日志已落盘",
    "identity.loaded": "从本地身份文件恢复身份",
    "identity.registered": "向注册中心注册新身份",

    # —— 服务端：签名与密钥 ——
    "server.signature_ok": "服务端已用登记公钥验证信封签名",
    "server.bad_signature": "服务端发现签名无效，拒绝投递",
    "server.key_mismatch": "信封公钥与登记公钥不一致，拒绝投递",
    "server.unsigned_rejected": "注册中心要求签名，但收到未签名信封，已拒绝",
    "server.send_unsigned": "该身份未登记公钥，消息未签名（已在审计中标记）",

    # —— 服务端控制面 ——
    "server.accept": "服务端受理该请求",
    "server.reject": "服务端拒绝该请求",
    "server.purge": "服务端清理过期数据（审计日志不允许在此列）",

    # —— 同机会话互信（v0.3）——
    # 这条记录的意义是：消息没走好友审批，但**不是没人管**。
    # 事后必须能回答"它凭什么发得出去"，所以放行也要有理由码。
    "mesh.local_trust": "同一台机器上的会话互发消息，按 local_mesh 免好友审批放行",
    "mesh.deny_friends": "非同好友且未开启同机互信，消息被拒",
}

# 哪些结果算"被挡下来了"，用于统计与告警。
DENY_REASONS = {k for k, v in REASONS.items() if ".deny" in k or k.endswith(("reject", "dropped"))}
OVERRIDE_REASONS = {k for k in REASONS if k.endswith(".override")}


class AuditError(RuntimeError):
    """审计写入失败。默认策略是**失败即中止业务动作**，而不是静默降级。"""


# ----------------------------------------------------------------------
# 脱敏工具：进入日志的一切文本都要先过这里
# ----------------------------------------------------------------------
_SENSITIVE_PATTERNS: List[Tuple[re.Pattern, str]] = [
    (re.compile(r"(?i)\b(?:sk|ak|pk|ghp|gho|github_pat|xoxb|eyJ)[-_A-Za-z0-9]{12,}"), "<KEY>"),
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----"), "<PRIVATE_KEY>"),
    (re.compile(r"(?i)\b(?:password|passwd|pwd|secret|token)\s*[=:]\s*\S+"), "<CREDENTIAL>"),
    (re.compile(r"\b\d{17}[\dXx]\b"), "<ID_CARD>"),
    (re.compile(r"(?<!\d)1[3-9]\d{9}(?!\d)"), "<PHONE>"),
    (re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"), "<IP>"),
    (re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"), "<EMAIL>"),
    (re.compile(r"(?i)\b(?:https?|ftp|redis|mysql|postgres(?:ql)?|mongodb|amqp)://[^\s\"']+"), "<URL>"),
    (re.compile(r"\b[0-9a-fA-F]{32,}\b"), "<HEX>"),
    (re.compile(r"\b[A-Za-z0-9+/=_-]{40,}\b"), "<TOKEN>"),
]


def scrub(text: str, limit: int = 0) -> str:
    """把文本变成"可以写进磁盘"的样子。

    先按敏感模式替换，再按需截断。顺序不能反：先截断会把
    密钥切成两半，导致正则匹配不上，反而漏出去。
    """
    if not text:
        return ""
    out = str(text)
    for rx, repl in _SENSITIVE_PATTERNS:
        out = rx.sub(repl, out)
    out = out.replace("\n", "\\n").replace("\r", "")
    if limit and len(out) > limit:
        out = out[:limit] + f"…(+{len(out) - limit})"
    return out


def mask(value: str, keep: int = 2) -> str:
    """极短掩码，只留首尾各 keep 个字符。用于必须保留一点辨识度的场景。"""
    s = str(value)
    if len(s) <= keep * 2:
        return "*" * len(s)
    return f"{s[:keep]}{'*' * min(12, len(s) - keep * 2)}{s[-keep:]}"


def fingerprint(payload: Any) -> Dict[str, Any]:
    """给一段内容算指纹。日志里存这个，不存原文。"""
    raw = payload if isinstance(payload, str) else json.dumps(payload, **_CANON)
    data = raw.encode("utf-8")
    return {"sha256": hashlib.sha256(data).hexdigest()[:32], "bytes": len(data)}


def _now() -> Tuple[float, str]:
    t = time.time()
    return t, datetime.fromtimestamp(t, CST).isoformat(timespec="milliseconds")


def _digest(rec: Dict[str, Any]) -> str:
    body = {k: v for k, v in rec.items() if k != "h"}
    return hashlib.sha256(json.dumps(body, **_CANON).encode("utf-8")).hexdigest()


# ----------------------------------------------------------------------
# 审计日志
# ----------------------------------------------------------------------
class AuditLog:
    """追加写的 JSONL 审计链。一个进程一条链，多进程自动分链，互不污染。

    参数：
      root          日志目录，通常 <home>/logs
      actor         本进程的身份，如 "agent:agt-xxx" / "service:registry"
      preview_chars 每条记录允许保留的内容预览长度，**默认 0 = 完全不存内容**
      max_bytes     单文件上限，超过则轮转（链在文件间保持连续）
      fsync_deny    deny/override 类记录是否强制落盘（默认 True）
      anchor_hook   可选回调，收到 (seq, h) 用于把链头锚到外部系统

    关于 preview_chars 的默认值，这里有个刻意的取舍：
    本工具的职责是"别把内网信息带出去"，那么它自己的日志就没有资格
    在磁盘上留下第二份原文副本。所以默认 0。
    排查时靠 trace_id + 内容指纹 + 规则名 + 长度已经足够定位；
    真要看原文，显式设 preview_chars=48，并且清楚你在磁盘上留了什么。
    """

    def __init__(self, root: str, actor: str, preview_chars: int = 0,
                 max_bytes: int = 8 * 1024 * 1024, fsync_deny: bool = True,
                 anchor_hook: Optional[Callable[[int, str], None]] = None,
                 enabled: bool = True, readonly: bool = False) -> None:
        self.root = root
        self.actor = actor
        self.preview_chars = max(0, int(preview_chars))
        self.max_bytes = max(64 * 1024, int(max_bytes))
        self.fsync_deny = fsync_deny
        self.anchor_hook = anchor_hook
        self.enabled = enabled
        self.readonly = readonly
        self.errors = 0

        self.chain = "main"
        self._fd: Optional[int] = None
        self._lock_fd: Optional[int] = None
        self._path = ""
        self._bytes = 0
        self._seq = 0
        self._prev = ""

        if readonly:
            # 只读模式：不抢锁、不开文件、不写 HEAD。
            # 查日志时最不该发生的事，就是"来了个查日志的人，顺手把证据目录改了"。
            return
        if not self.enabled:
            return
        os.makedirs(self.root, exist_ok=True)
        self._acquire_chain()
        self._recover()
        # 进程退出时确保落盘并释放链锁。CLI 这类短命进程不显式 close，
        # 少了这一步，最后几条记录可能只停在页缓存里。
        atexit.register(self.close)

    # ---------------- 链身份与接续 ----------------
    def _acquire_chain(self) -> None:
        """抢主链锁；抢不到就用 pid 独立链。

        为什么用**操作系统级文件锁**而不是"写个 pid 文件"：
        pid 文件在进程被杀、崩溃、断电时会残留，下一个进程看到锁还在，
        就以为自己不是主进程，于是每次启动都新开一条链。
        CLI 这种"一条命令一个进程"的用法下，一天能碎出几百条链，
        输出一屏全是链名，谁也看不出发生了什么——日志就白记了。
        OS 文件锁在进程退出时由内核自动释放，没有僵尸锁问题。

        为什么不直接让多进程写同一条链：并发追加会让 prev/h 交织，
        链一断整份就不可验证。宁可分成多条链，也不要一条"看起来完整、
        实际验不过"的链——后者比没有日志更危险，因为它会让人误信。
        """
        lock = os.path.join(self.root, ".chain.lock")
        try:
            fd = os.open(lock, os.O_CREAT | os.O_RDWR, 0o600)
        except OSError:
            self.chain = f"p{os.getpid()}"
            return
        try:
            if os.name == "nt":
                import msvcrt
                msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self._lock_fd = fd        # 持有到进程退出，内核负责释放
            self.chain = "main"
        except OSError:
            try:
                os.close(fd)
            except OSError:
                pass
            self.chain = f"p{os.getpid()}"

    def _recover(self) -> None:
        """从已有文件恢复 seq / prev，保证重启后链不断。

        两个关键点：
        1) 重启必须接续，否则"重启大法"就能重置计数，日志碎成各自为政的碎片；
        2) 扫描范围必须包含 archive/ —— 归档之后如果从 seq=1 重新开始，
           校验时会看到"同一个链里第 7 条后面跟着第 1 条"，直接判定为篡改。
           归档本来是为了保存证据，结果把自己变成"证据已被破坏"，那就荒唐了。
        """
        last_seq, last_h = 0, ""
        for p in self._all_files():
            if _chain_of(p) != self.chain:
                continue
            try:
                with open(p, "r", encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            d = json.loads(line)
                        except json.JSONDecodeError:
                            continue
                        if int(d.get("seq", 0)) >= last_seq:
                            last_seq, last_h = int(d.get("seq", 0)), str(d.get("h", ""))
            except OSError:
                continue
        self._seq, self._prev = last_seq, last_h
        self._open_next()

    def _segments(self, chain: str) -> List[str]:
        if not os.path.isdir(self.root):
            return []
        out = []
        for name in os.listdir(self.root):
            if name.startswith(f"audit.{chain}") and name.endswith(".jsonl"):
                out.append(os.path.join(self.root, name))
        return out

    def _open_next(self) -> None:
        """接着最后一段写；只有真写满了才开新段。

        这里如果图省事写成"每次启动开新文件"，CLI 每跑一条命令就多一个文件，
        一周后目录里有几千个几 KB 的文件。日志系统自己变成噪音源，
        是比没有日志更糟的结果。
        """
        segs = self._segments(self.chain)
        if segs:
            last = max(segs, key=_seg_index)
            try:
                if os.path.getsize(last) < self.max_bytes:
                    self._path = last
                    self._fd = os.open(last, os.O_CREAT | os.O_WRONLY | os.O_APPEND, 0o600)
                    self._bytes = os.path.getsize(last)
                    return
            except OSError:
                pass
        n = max([_seg_index(p) for p in self._all_files()
                 if _chain_of(p) == self.chain] + [-1]) + 1
        self._path = os.path.join(self.root, f"audit.{self.chain}.{n}.jsonl")
        self._fd = os.open(self._path, os.O_CREAT | os.O_WRONLY | os.O_APPEND, 0o600)
        self._bytes = os.path.getsize(self._path) if os.path.exists(self._path) else 0

    # ---------------- 写 ----------------
    def write(self, event: str, decision: str, reason: str,
              trace: Optional[str] = None, detail: Optional[Dict[str, Any]] = None,
              evidence: Optional[Dict[str, Any]] = None,
              preview: Optional[str] = None) -> Optional[Dict[str, Any]]:
        """写一条审计记录。reason 必须是 REASONS 里的键。

        decision 取值：allow / redact / deny / drop / note
        写失败时：deny 类记录抛 AuditError（宁可业务失败，也不能"拦了却没记录"），
        其余类别只累计 errors。这个差别是故意的——**拦了不记录 = 无法追责**。
        """
        if not self.enabled or self.readonly:
            return None
        if reason not in REASONS:
            raise AuditError(f"未登记的理由码 {reason!r}，禁止写入自由文本理由")
        if decision not in ("allow", "redact", "deny", "drop", "note"):
            raise AuditError(f"非法 decision {decision!r}")

        ts, iso = _now()
        self._seq += 1
        rec: Dict[str, Any] = {
            "v": LOG_SCHEMA,
            "seq": self._seq,
            "ts": round(ts, 6),
            "iso": iso,
            "chain": self.chain,
            "trace": trace or "",
            "event": event,
            "actor": self.actor,
            "decision": decision,
            "reason": reason,
            "detail": _safe_detail(detail or {}, self.preview_chars),
            "evidence": _safe_detail(evidence or {}, 0),
            "prev": self._prev,
        }
        if preview and self.preview_chars:
            rec["preview"] = scrub(preview, self.preview_chars)
        if preview:
            # 不存原文也留一个短指纹：用来判断"两条记录说的是不是同一段话"，
            # 这是排查循环对话时最常用的一条线索。
            rec["preview_fp"] = hashlib.sha256(
                str(preview).encode("utf-8")).hexdigest()[:16]
            rec["preview_len"] = len(str(preview))
        rec["h"] = _digest(rec)

        line = json.dumps(rec, **_CANON) + "\n"
        try:
            assert self._fd is not None
            os.write(self._fd, line.encode("utf-8"))
            self._bytes += len(line.encode("utf-8"))
            hard = decision in ("deny", "drop") or reason in OVERRIDE_REASONS
            # 拦截类必须真落盘：它可能是日后唯一的证据。
            # 放行类按 256KB 粒度 fsync，性能与可靠性折中。
            if (hard and self.fsync_deny) or self._bytes % (256 * 1024) < len(line.encode("utf-8")):
                os.fsync(self._fd)
            if self._bytes >= self.max_bytes:
                os.close(self._fd)
                self._fd = None
                self._open_next()
        except OSError as e:
            self.errors += 1
            if decision in ("deny", "drop") or reason in OVERRIDE_REASONS:
                raise AuditError(f"审计写入失败，已中止动作：{e}") from e
            return None

        self._prev = rec["h"]
        self._write_head()
        if self.anchor_hook is not None and hard:
            try:
                self.anchor_hook(self._seq, rec["h"])
            except Exception:
                pass    # 外部锚定失败不影响本地留痕，已记在 errors 之外
        return rec

    def _write_head(self) -> None:
        """HEAD 锚点独立于日志文件，用来发现"尾部被截掉"。"""
        try:
            hp = os.path.join(self.root, f"HEAD.{self.chain}")
            tmp = hp + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump({"seq": self._seq, "h": self._prev, "ts": time.time()},
                          f, ensure_ascii=False)
            os.replace(tmp, hp)
        except OSError:
            self.errors += 1

    def close(self) -> None:
        if self._fd is not None:
            try:
                os.fsync(self._fd)
                os.close(self._fd)
            except OSError:
                pass
            self._fd = None
        if self._lock_fd is not None:
            try:
                os.close(self._lock_fd)     # 关掉即释放链锁，别的进程可接管
            except OSError:
                pass
            self._lock_fd = None

    # ---------------- 校验 ----------------
    def verify(self) -> Dict[str, Any]:
        """逐条重算哈希链并检查断点。

        检出四类问题：哈希不符（内容被改）、prev 不符（顺序被调/插入）、
        seq 跳号（中间被删）、HEAD 之外无记录（尾部被删）。
        """
        report: Dict[str, Any] = {"ok": True, "records": 0, "chains": {},
                                  "errors": [], "verified_at": _now()[1]}
        files = self._all_files()
        by_chain: Dict[str, List[str]] = {}
        for p in files:
            chain = _chain_of(p)
            by_chain.setdefault(chain, []).append(p)

        for chain, paths in sorted(by_chain.items()):
            prev, expect, total = "", None, 0
            first = True
            # 按"文件内第一条记录的 seq"排序，而不是按文件名序号。
            # 归档会把文件挪到 archive/ 子目录，用文件名排序会把新旧段搞反，
            # 于是好端端的日志被验成"顺序被调换"。
            for p in sorted(paths, key=lambda x: (_first_seq(x), _seg_index(x))):
                try:
                    fh = open(p, "r", encoding="utf-8")
                except OSError as e:
                    report["errors"].append({"file": p, "kind": "unreadable", "detail": str(e)})
                    continue
                with fh:
                    for lineno, line in enumerate(fh, 1):
                        line = line.strip()
                        if not line:
                            continue
                        total += 1
                        try:
                            rec = json.loads(line)
                        except json.JSONDecodeError:
                            report["errors"].append({"file": os.path.basename(p), "line": lineno,
                                                     "kind": "bad_json"})
                            continue
                        if expect is None:
                            # 链的起点不一定是 1：早期记录可能已归档到别处。
                            expect = int(rec.get("seq", 1))
                        if rec.get("h") != _digest(rec):
                            report["errors"].append({"file": os.path.basename(p), "line": lineno,
                                                     "seq": rec.get("seq"), "kind": "hash_mismatch",
                                                     "detail": "内容与哈希不符，记录被改动过"})
                        if not first and rec.get("prev") != prev:
                            report["errors"].append({"file": os.path.basename(p), "line": lineno,
                                                     "seq": rec.get("seq"), "kind": "prev_mismatch",
                                                     "detail": "前驱哈希不符，记录被插入或调换过顺序"})
                        if int(rec.get("seq", 0)) != expect:
                            report["errors"].append({"file": os.path.basename(p), "line": lineno,
                                                     "seq": rec.get("seq"), "kind": "seq_gap",
                                                     "detail": f"期望 {expect}，实际 {rec.get('seq')}，中间可能有记录被删"})
                        prev = str(rec.get("h", ""))
                        expect = int(rec.get("seq", expect)) + 1
                        first = False
            # HEAD 比对
            hp = os.path.join(self.root, f"HEAD.{chain}")
            head_seq = None
            if os.path.exists(hp):
                try:
                    with open(hp, "r", encoding="utf-8") as f:
                        head_seq = int(json.load(f).get("seq", 0))
                except (OSError, ValueError, json.JSONDecodeError):
                    head_seq = None
            if head_seq is not None and total and head_seq > expect - 1:
                report["errors"].append({"file": f"HEAD.{chain}", "kind": "tail_truncated",
                                         "detail": f"HEAD 记录到第 {head_seq} 条，日志只到第 {expect - 1} 条，尾部记录缺失"})
            report["chains"][chain] = {"records": total,
                                       "last_seq": (expect - 1) if expect else 0}
            report["records"] += total

        report["ok"] = not report["errors"]
        return report

    def _all_files(self) -> List[str]:
        out: List[str] = []
        for base, _dirs, names in os.walk(self.root):
            for n in names:
                if n.startswith("audit.") and n.endswith(".jsonl"):
                    out.append(os.path.join(base, n))
        return out

    def _head_files(self) -> List[str]:
        if not os.path.isdir(self.root):
            return []
        return [os.path.join(self.root, n) for n in os.listdir(self.root)
                if n.startswith("HEAD.") and not n.endswith(".tmp")]

    # ---------------- 查询 ----------------
    def read(self, limit: int = 100, trace: Optional[str] = None,
             event: Optional[str] = None, decision: Optional[str] = None,
             reason: Optional[str] = None, since: float = 0.0,
             chain: Optional[str] = None) -> List[Dict[str, Any]]:
        """按条件读记录。返回按 seq 升序，最多 limit 条（取最新的）。"""
        ev = re.compile(event) if event else None
        rs = re.compile(reason) if reason else None
        out: List[Dict[str, Any]] = []
        for p in self._all_files():
            if chain and _chain_of(p) != chain:
                continue
            try:
                with open(p, "r", encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            rec = json.loads(line)
                        except json.JSONDecodeError:
                            continue
                        if float(rec.get("ts", 0)) < since:
                            continue
                        if trace and rec.get("trace") != trace:
                            continue
                        if ev and not ev.search(str(rec.get("event", ""))):
                            continue
                        if decision and rec.get("decision") != decision:
                            continue
                        if rs and not rs.search(str(rec.get("reason", ""))):
                            continue
                        out.append(rec)
            except OSError:
                continue
        out.sort(key=lambda r: (r.get("ts", 0), r.get("seq", 0)))
        return out[-limit:] if limit and len(out) > limit else out

    def tail(self, n: int = 20) -> List[Dict[str, Any]]:
        return self.read(limit=n)

    def stats(self) -> Dict[str, Any]:
        recs = self.read(limit=0)
        by_dec: Dict[str, int] = {}
        by_reason: Dict[str, int] = {}
        for r in recs:
            by_dec[r.get("decision", "?")] = by_dec.get(r.get("decision", "?"), 0) + 1
            by_reason[r.get("reason", "?")] = by_reason.get(r.get("reason", "?"), 0) + 1
        return {"total": len(recs), "by_decision": by_dec, "by_reason": by_reason,
                "denied": sum(v for k, v in by_dec.items() if k in ("deny", "drop")),
                "overrides": sum(by_reason.get(k, 0) for k in OVERRIDE_REASONS)}

    # ---------------- 归档 ----------------
    def seal(self, name: Optional[str] = None) -> Dict[str, Any]:
        """把当前文件封存为证据包：写 MANIFEST（每个文件的 sha256、条数、首尾哈希），
        移入 archive/<name>/。封存只加不减，删数据不在这个模块的职责里。
        """
        self.close()
        name = name or datetime.now(CST).strftime("%Y%m%d-%H%M%S")
        dest = os.path.join(self.root, "archive", name)
        os.makedirs(dest, exist_ok=True)
        files = []
        for p in self._all_files():
            if os.path.dirname(p) != self.root:
                continue
            data = open(p, "rb").read()
            n = data.count(b"\n")
            files.append({"name": os.path.basename(p),
                          "sha256": hashlib.sha256(data).hexdigest(),
                          "bytes": len(data),
                          "records": n})
            os.replace(p, os.path.join(dest, os.path.basename(p)))
        for h in self._head_files():
            os.replace(h, os.path.join(dest, os.path.basename(h)))
        manifest = {"sealed_at": _now()[1], "name": name,
                    "files": files, "chain_stats": self.stats()}
        with open(os.path.join(dest, "MANIFEST.json"), "w", encoding="utf-8") as f:
            json.dump(manifest, f, ensure_ascii=False, indent=2, sort_keys=True)
        return manifest


# ----------------------------------------------------------------------
# 内部工具
# ----------------------------------------------------------------------
def _chain_of(path: str) -> str:
    """从文件名 audit.<chain>.<n>.jsonl 里取 chain。"""
    base = os.path.basename(path)
    parts = base.split(".")
    return parts[1] if len(parts) >= 4 else "main"


def _seg_index(path: str) -> int:
    base = os.path.basename(path)
    parts = base.split(".")
    try:
        return int(parts[-2])
    except (IndexError, ValueError):
        return 0


def _first_seq(path: str) -> int:
    """读文件里第一条记录的 seq，用于跨目录排序（archive 与现行段混排）。"""
    try:
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    return int(json.loads(line).get("seq", 0))
    except (OSError, ValueError, json.JSONDecodeError):
        pass
    return 0


_ID_RX = re.compile(r"^(?:agt|grp|msg|conv|frq|prp|trace|idem|evt|rq)-[A-Za-z0-9]{4,}$")

# 这些字段里的字符串必须完整保留，不做长度遮蔽。
# force_reason 是"谁批准了这次放行、为什么"的唯一书面依据，
# 把它截成 <str:23> 等于把责任链上最关键的一环弄丢了。
_VERBATIM_KEYS = {"force_reason", "reason", "why", "note", "suggestion"}


def _safe_detail(d: Dict[str, Any], preview_chars: int) -> Dict[str, Any]:
    """detail 只允许标量和小结构；字符串一律脱敏。

    规则（preview_chars=0 默认）：
      · 长得像 ID 的（agt-xxx / trace-xxx / conv-xxx）原样保留——
        ID 本身不敏感，而排查时"对端是谁"是第一必须要回答的问题；
      · _VERBATIM_KEYS 里的完整保留（已过敏感模式脱敏）——
        它们承载的是责任说明，不是业务内容；
      · 其余长于 16 字符的字符串只留长度占位，不落原文。
    """
    def one(k: str, v: Any, cap: int) -> Any:
        s = scrub(str(v), 0)
        if _ID_RX.match(s):
            return s
        if k in _VERBATIM_KEYS:
            return scrub(str(v), 240)
        if preview_chars == 0 and len(s) > 16:
            return f"<str:{len(s)}>"
        return s[:cap] if cap else s

    out: Dict[str, Any] = {}
    for k, v in d.items():
        if isinstance(v, (int, float, bool)) or v is None:
            out[k] = v
        elif isinstance(v, str):
            out[k] = one(str(k), v, preview_chars or 0)
        elif isinstance(v, (list, tuple)):
            out[k] = [one(str(k), x, 40) for x in list(v)[:20]]
        elif isinstance(v, dict):
            out[k] = {str(kk): one(str(kk), vv, 40) for kk, vv in list(v.items())[:20]}
        else:
            out[k] = one(str(k), v, 60)
    return out
