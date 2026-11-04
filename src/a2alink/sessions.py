"""会话身份：把「一个对话窗口」映射成一个稳定的 Agent 身份。

## 为什么需要这一层

Agent 的 Skill 有一个绕不开的事实：**每次被调用都是一个新进程**，没有
内存可依赖。如果每次调用都随手生成一个 agent 名，同一个对话跑三遍，注册
中心里就会多出三个身份——消息投给谁、谁回的、审计链上这两条属于同一个
人，全都说不清。

好在宿主环境里本来就有一个稳定的东西：会话 ID（WorkBuddy 是
``CODEBUDDY_SESSION_ID``，Claude Code 是 ``CLAUDE_SESSION_ID``）。一个对话
窗口一个 ID，关掉重开才换。用它派生 agent 名和 home 目录，同一个对话无论
被调用多少次，拿到的都是同一个身份、同一把钥匙、同一条审计链。

## 三条设计约束

1. **agent_name 一旦定下就不许改**。
   改名的代价不是"显示变了"，而是注册中心里换了一个人：之前加的好友、
   群的成员关系、对端固定的公钥，全部失联。所以 ``label``（人看的外号）
   可以随时改，``agent_name``（协议里的身份）在首次绑定后冻结。

2. **没有会话 ID 时不许瞎猜一个全新身份**。
   猜错的后果是消息发出去没人收。宁可复用最近活跃的会话并**明确告诉你**，
   也不要静默新建一个孤岛。用户可以用 ``--as`` 覆盖。

3. **别名表是纯本地文件，不进网络**。
   它记录"我叫 ops 的那个对话是哪台机器上的哪个 UUID"，这种东西只在本机
   有意义，出去了就是给自己递信息。
"""

from __future__ import annotations

import json
import os
import re
import time
from typing import Any, Dict, List, Optional

VERSION = 1

# 环境变量里可能出现会话 ID 的位置，按优先级排列。
# 允许用户用 A2ALINK_SESSION 手动指定（填别名或 UUID 都行）。
SESSION_ENV_KEYS = (
    "A2ALINK_SESSION",
    "CODEBUDDY_SESSION_ID",
    "CLAUDE_SESSION_ID",
    "WORKBUDDY_SESSION_ID",
    "A2A_SESSION_ID",
)

# 别名不能叫这些：会和命令语义打架。
RESERVED_LABELS = {"me", "self", "all", "everyone", "system", "a2alink"}

# 别名允许中文——用户给对话起名"运维""写手"是自然的事。
LABEL_RE = re.compile(r"[A-Za-z0-9_\-\u4e00-\u9fa5]{2,24}")

# 会话 ID 只接受这些字符。宿主给的是 UUID，但 A2ALINK_SESSION 是用户输入，
# 它会被拼进文件路径，必须挡掉 ``../`` 这类东西。
SID_RE = re.compile(r"[A-Za-z0-9_\-.]{4,80}")


class SessionError(ValueError):
    """会话身份相关的人为错误，消息面向使用者。"""


def session_id_from_env(env: Optional[Dict[str, str]] = None) -> Optional[str]:
    """从环境变量里找当前会话 ID。找不到返回 None，不造值。"""
    e = os.environ if env is None else env
    for k in SESSION_ENV_KEYS:
        v = (e.get(k) or "").strip()
        if v and SID_RE.fullmatch(v):
            return v
    return None


def _default_root() -> str:
    return os.environ.get("A2ALINK_HOME") or os.path.join(
        os.path.expanduser("~"), ".a2alink")


def short(sid: str) -> str:
    """会话 ID 的人读前缀。去掉分隔符取 10 位：足够避免同机碰撞，
    又比整串 UUID 好念——这个名字会出现在每一条消息的署名里。"""
    clean = re.sub(r"[^A-Za-z0-9]", "", sid)
    return (clean or sid)[:10]


class _FileLock:
    """跨进程互斥。别名表会被并发的多个对话同时写，读-改-写必须串行。

    不用 pid 锁文件：进程崩溃留下残留文件，下次启动就永远拿不到锁。
    用内核级文件锁，进程退出（包括被 kill）由内核自动释放。
    """

    def __init__(self, path: str) -> None:
        self.path = path
        self.fd: Optional[int] = None
        self.locked = False

    def __enter__(self) -> "_FileLock":
        os.makedirs(os.path.dirname(self.path) or ".", exist_ok=True)
        self.fd = os.open(self.path, os.O_RDWR | os.O_CREAT, 0o600)
        try:
            if os.name == "nt":
                import msvcrt
                msvcrt.locking(self.fd, msvcrt.LK_LOCK, 1)
            else:
                import fcntl
                fcntl.flock(self.fd, fcntl.LOCK_EX)
        except OSError:
            # 拿不到锁不阻断操作：别名表是便利设施，不是安全边界。
            # 但要让调用方知道（返回 self.locked=False）。
            self.locked = False
        else:
            self.locked = True
        return self

    def __exit__(self, *exc: Any) -> None:
        if self.fd is not None:
            try:
                if os.name == "nt":
                    import msvcrt
                    try:
                        msvcrt.locking(self.fd, msvcrt.LK_UNLCK, 1)
                    except OSError:
                        pass
                else:
                    import fcntl
                    fcntl.flock(self.fd, fcntl.LOCK_UN)
            finally:
                os.close(self.fd)
                self.fd = None


class SessionStore:
    """``~/.a2alink/sessions.json`` 的读写封装。

    结构::

        {
          "version": 1,
          "sessions": {
            "<sid>": {"sid":..., "label":..., "agent_name":...,
                      "home":..., "created_at":..., "last_seen":...}
          },
          "aliases": {"<label 小写>": "<sid>"}
        }
    """

    def __init__(self, root: Optional[str] = None) -> None:
        self.root = root or _default_root()
        self.path = os.path.join(self.root, "sessions.json")
        self._lock_path = self.path + ".lock"

    # ---------------------------------------------------------------- IO
    def _read(self) -> Dict[str, Any]:
        try:
            with open(self.path, "r", encoding="utf-8") as f:
                d = json.load(f)
            if not isinstance(d, dict):
                raise ValueError("not a dict")
        except (OSError, ValueError):
            return {"version": VERSION, "sessions": {}, "aliases": {}}
        d.setdefault("version", VERSION)
        d.setdefault("sessions", {})
        d.setdefault("aliases", {})
        return d

    def _write(self, d: Dict[str, Any]) -> None:
        os.makedirs(self.root, exist_ok=True)
        tmp = self.path + f".tmp{os.getpid()}"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(d, f, ensure_ascii=False, indent=2, sort_keys=True)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, self.path)          # 原子替换，断电不会留下半个文件
        try:
            os.chmod(self.path, 0o600)      # 别名表里有会话 UUID，不给别人看
        except OSError:
            pass

    # ------------------------------------------------------------ 查询
    def all(self) -> Dict[str, Dict[str, Any]]:
        return dict(self._read()["sessions"])

    def get(self, sid: str) -> Optional[Dict[str, Any]]:
        return self._read()["sessions"].get(sid)

    def by_label(self, label: str) -> Optional[Dict[str, Any]]:
        d = self._read()
        sid = d["aliases"].get(str(label).strip().lower())
        return d["sessions"].get(sid) if sid else None

    def latest(self) -> Optional[Dict[str, Any]]:
        """最近活跃的会话。没有会话 ID 时的兜底，调用方**必须**把这件事说出来。"""
        rows = list(self._read()["sessions"].values())
        if not rows:
            return None
        return max(rows, key=lambda r: float(r.get("last_seen") or 0))

    def resolve(self, who: str) -> Optional[str]:
        """把 ``@ops`` / ``ops`` / ``<sid>`` / ``<sid 前缀>`` 解析成完整 sid。"""
        w = str(who or "").strip().lstrip("@")
        if not w:
            return None
        d = self._read()
        if w in d["sessions"]:
            return w
        rec = d["sessions"].get(d["aliases"].get(w.lower(), ""))
        if rec:
            return rec["sid"]
        # 前缀匹配：允许 a2alink say 3f2a1b44 "..."，但必须唯一
        hits = [s for s in d["sessions"] if s.startswith(w)]
        if len(hits) == 1:
            return hits[0]
        if len(hits) > 1:
            raise SessionError(f"前缀 {w!r} 匹配到多个会话（{len(hits)} 个），请写长一点")
        return None

    # ------------------------------------------------------------ 写入
    def bind(self, sid: str, label: Optional[str] = None,
             agent_name: Optional[str] = None) -> Dict[str, Any]:
        """建立或更新一个会话身份。返回记录。

        ``agent_name`` 已存在时**不会被覆盖**——除非显式传入且记录里还没有。
        这是本模块最重要的一条约束，见文件头注释第 1 条。
        """
        if not SID_RE.fullmatch(sid or ""):
            raise SessionError(f"会话 ID 非法: {sid!r}")

        label_clean = None
        if label is not None:
            label_clean = str(label).strip()
            if not LABEL_RE.fullmatch(label_clean):
                raise SessionError(
                    "别名要求 2-24 个字符，只能用中英文、数字、下划线、短横线")
            if label_clean.lower() in RESERVED_LABELS:
                raise SessionError(f"{label_clean!r} 是保留字，换一个")

        with _FileLock(self._lock_path):
            d = self._read()
            now = time.time()
            rec = d["sessions"].get(sid)
            if rec is None:
                rec = {
                    "sid": sid,
                    "label": None,
                    "agent_name": agent_name or f"s-{short(sid)}",
                    "home": os.path.join(self.root, "sessions", short(sid)),
                    "created_at": now,
                    "last_seen": now,
                }
                d["sessions"][sid] = rec
            else:
                rec["last_seen"] = now
                rec.setdefault("home", os.path.join(
                    self.root, "sessions", short(sid)))
                # 兼容早期记录：没有 agent_name 的补一个，已有的一律不动
                if not rec.get("agent_name"):
                    rec["agent_name"] = agent_name or f"s-{short(sid)}"

            if label_clean:
                key = label_clean.lower()
                owner = d["aliases"].get(key)
                if owner and owner != sid:
                    raise SessionError(
                        f"别名 {label_clean!r} 已被会话 {short(owner)} 占用。"
                        f"先 a2alink session name --release 释放它，或换个名字。")
                # 一个会话只保留一个别名：换名时把旧键删掉，否则
                # 旧名会指向一个改了名的人，下次 @旧名 就发错人。
                old = rec.get("label")
                if old and old.lower() != key:
                    d["aliases"].pop(old.lower(), None)
                d["aliases"][key] = sid
                rec["label"] = label_clean

            self._write(d)
            return dict(rec)

    def touch(self, sid: str) -> None:
        """只更新 last_seen。高频调用，出错就静默——统计不该影响主流程。"""
        try:
            with _FileLock(self._lock_path):
                d = self._read()
                if sid in d["sessions"]:
                    d["sessions"][sid]["last_seen"] = time.time()
                    self._write(d)
        except (OSError, SessionError, ValueError):
            pass

    def release_label(self, label: str) -> bool:
        with _FileLock(self._lock_path):
            d = self._read()
            key = str(label).strip().lower()
            sid = d["aliases"].pop(key, None)
            if not sid:
                return False
            rec = d["sessions"].get(sid)
            if rec and str(rec.get("label", "")).lower() == key:
                rec["label"] = None
            self._write(d)
            return True

    def forget(self, sid: str, drop_files: bool = False) -> bool:
        """从表里移除。``drop_files`` 才会删身份目录，默认不删。

        默认不删的理由：身份目录里有私钥和审计链，删掉就再也验证不了
        历史消息是谁发的。要删必须由人明确要求。
        """
        with _FileLock(self._lock_path):
            d = self._read()
            rec = d["sessions"].pop(sid, None)
            if not rec:
                return False
            for k, v in list(d["aliases"].items()):
                if v == sid:
                    d["aliases"].pop(k, None)
            self._write(d)
        if drop_files and rec.get("home"):
            import shutil
            shutil.rmtree(rec["home"], ignore_errors=True)
        return True


class SessionIdentity:
    """当前进程所属的会话身份。"""

    def __init__(self, sid: str, record: Dict[str, Any], source: str) -> None:
        self.sid = sid
        self.record = record
        self.source = source        # env / alias / latest / fallback

    @property
    def label(self) -> Optional[str]:
        return self.record.get("label")

    @property
    def agent_name(self) -> str:
        return self.record["agent_name"]

    @property
    def home(self) -> str:
        return self.record["home"]

    @property
    def display(self) -> str:
        return f"@{self.label}" if self.label else short(self.sid)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "session_id": self.sid,
            "label": self.label,
            "agent_name": self.agent_name,
            "home": self.home,
            "source": self.source,
            "created_at": self.record.get("created_at"),
            "last_seen": self.record.get("last_seen"),
        }


def current(store: Optional[SessionStore] = None,
            who: Optional[str] = None,
            env: Optional[Dict[str, str]] = None,
            create: bool = True) -> SessionIdentity:
    """解析出当前会话身份。

    ``who`` 用于 ``--as`` 显式指定（别名或 sid）。来源优先级：
    ``--as`` > 环境变量会话 ID > 别名 > 最近活跃 > 新建 fallback。

    返回值里的 ``source`` 会告诉调用方是不是猜的，好让人在输出里说明。
    """
    st = store or SessionStore()
    e = os.environ if env is None else env

    if who:
        sid = st.resolve(who)
        if not sid:
            # 允许 --as 一个新别名，直接为它造一个稳定的会话 ID。这样在没有
            # 任何宿主环境变量的场景（纯 shell、cron、CI）里也能起独立身份。
            # 用名字的哈希当 ID，而不是直接用名字：中文名进不了文件路径和
            # 注册中心的名称规则，而哈希是稳定的——同一个名字永远是同一个人。
            name = str(who).strip().lstrip("@")
            if not LABEL_RE.fullmatch(name):
                raise SessionError(
                    f"找不到会话 {who!r}，它也不像合法的别名"
                    f"（2-24 个中英文/数字/_-）。")
            import hashlib
            synth = "alias-" + hashlib.sha256(
                name.encode("utf-8")).hexdigest()[:12]
            rec = st.bind(synth, label=name)
            return SessionIdentity(synth, rec, "explicit")
        rec = st.get(sid) or st.bind(sid)
        st.touch(sid)
        return SessionIdentity(sid, rec, "explicit")

    sid = session_id_from_env(e)
    if sid:
        # 已经认识的会话不重写文件——CLI 每条命令都跑一次，
        # 没必要为了刷新 last_seen 做两次全表序列化。
        rec = st.get(sid) or st.bind(sid)
        st.touch(sid)
        return SessionIdentity(sid, rec, "env")

    latest = st.latest()
    if latest:
        st.touch(latest["sid"])
        return SessionIdentity(latest["sid"], latest, "latest")

    if not create:
        raise SessionError(
            "没有检测到会话 ID，本机也还没有任何会话。"
            "请在新对话里调用，或用 --as <名字> 指定一个身份。")
    rec = st.bind("manual", label="manual", agent_name="s-manual")
    return SessionIdentity("manual", rec, "fallback")


def default_capabilities() -> List[str]:
    return []
