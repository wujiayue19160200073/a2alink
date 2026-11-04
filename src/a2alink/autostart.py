"""本地中继的自动拉起与停止。

## 为什么要有这一层

"一键安装"如果不能一键跑起来，就不叫一键。可现状是：想发消息，得先想起
去开一个终端跑 ``a2alink registry``。真正在用的人不会每次都记得，第一次忘了
就会以为"这工具坏了"。

所以让每条命令自己检查：中继活着就直接用，没活着就拉起来。

## 三条必须守住的边界

1. **只自动拉起回环地址上的中继**。
   ``--registry https://a2a.example.com`` 这种远端地址，本机没有任何权力
   去"拉起"它，探测失败就是失败，如实报错。跨机器自动重连是很危险的行为：
   它会让一个本该失败的连接变成"重试到某个偶然可用的东西上"。

2. **探活以端口上的服务自报家门为准，不看 pid 文件**。
   pid 文件会残留、会被复用。判断"这个端口上是不是 a2alink"只有一个可靠
   办法：问它 ``/healthz``，看 ``service`` 字段。

3. **停止只杀自己拉起来的进程**。
   端口活着但 pid 文件不存在，说明是用户手动起的，只报告不杀。杀错一个
   无关进程的代价，远大于让用户自己敲一次 Ctrl-C。
"""

from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
from typing import Any, Dict, Optional, Tuple
from urllib.parse import urlparse

LOOPBACK = {"127.0.0.1", "localhost", "::1"}
DEFAULT_PORT = 8787
START_TIMEOUT = 10.0
PROBE_TIMEOUT = 0.6


class AutoStartError(RuntimeError):
    """自动拉起失败。消息里要带得上日志尾巴，否则用户只能猜。"""


def _root() -> str:
    return os.environ.get("A2ALINK_HOME") or os.path.join(
        os.path.expanduser("~"), ".a2alink")


def split_registry(url: str) -> Tuple[str, int, bool]:
    """返回 (host, port, is_local)。解析失败按本机默认处理。"""
    try:
        u = urlparse(url)
        host = (u.hostname or "127.0.0.1").lower()
        port = u.port or DEFAULT_PORT
    except ValueError:
        return "127.0.0.1", DEFAULT_PORT, True
    return host, port, host in LOOPBACK


def probe(url: str, timeout: float = PROBE_TIMEOUT) -> Optional[Dict[str, Any]]:
    """问一句 /healthz。是 a2alink 就返回它的自述，否则 None。"""
    try:
        req = urllib.request.Request(url.rstrip("/") + "/healthz",
                                     headers={"User-Agent": "a2alink-probe"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            body = json.loads(r.read(4096).decode("utf-8") or "{}")
    except (urllib.error.URLError, OSError, ValueError, socket.timeout):
        return None
    if not isinstance(body, dict) or body.get("service") != "a2alink":
        # 端口上确实有东西，但不是我们。这是最容易被误判成"已就绪"的情况。
        return None
    return body


def _port_open(host: str, port: int, timeout: float = 0.25) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def _pid_path(port: int) -> str:
    return os.path.join(_root(), f"registry-{port}.pid")


def _log_path(port: int) -> str:
    return os.path.join(_root(), f"registry-{port}.log")


def read_pid(port: int) -> Optional[Dict[str, Any]]:
    try:
        with open(_pid_path(port), "r", encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return None


def _tail(path: str, n: int = 15) -> str:
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            lines = f.readlines()
        return "".join(lines[-n:]).strip()
    except OSError:
        return ""


def ensure(url: str, db: Optional[str] = None, quiet: bool = False,
           timeout: float = START_TIMEOUT, local_mesh: bool = True) -> Dict[str, Any]:
    """确保本机中继可用。已活着就什么都不做。

    返回 ``{"managed": bool, "started": bool, "url":..., "pid":..., "log":...}``。

    ``local_mesh`` 默认 True：自动拉起的中继是"我自己这台机器上的个人中继"，
    它的语义就是同机会话互通。第一次拉起时会明确打印这件事——默认值可以
    方便，但不能悄悄。已存在的中继不会被改写配置。
    """
    host, port, local = split_registry(url)
    if not local:
        # 远端中继：只探活，探不到就如实报错，不替用户做重试外的任何事。
        return {"managed": False, "started": False, "url": url,
                "alive": probe(url) is not None}

    if probe(url) is not None:
        return {"managed": True, "started": False, "url": url,
                "alive": True, "pid": (read_pid(port) or {}).get("pid")}

    if _port_open(host, port):
        # 端口被占但不是 a2alink。**不要**去猜"也许是旧版本"，直接说出来：
        # 换端口比杀掉一个不明进程安全得多。
        raise AutoStartError(
            f"端口 {port} 已被其他程序占用（不是 a2alink，/healthz 不认）。\n"
            f"请换一个端口：a2alink up --port 8788，"
            f"或 a2alink --registry http://127.0.0.1:8788 ...")

    root = _root()
    os.makedirs(root, exist_ok=True)
    db = db or os.path.join(root, "registry.sqlite3")
    logf = _log_path(port)

    # 参数走环境变量而不是拼进源码字符串：db 路径可能带引号、反斜杠、
    # 中文，拼字符串总有某个字符能把这条命令弄坏。JSON 一次解决。
    boot_args = ["registry", "--db", db, "--host", "127.0.0.1",
                 "--port", str(port)]
    if local_mesh:
        boot_args.append("--local-mesh")
    cmd = [sys.executable, "-c",
           "import json,os,sys;from a2alink.cli import main;"
           "sys.argv=['a2alink']+json.loads(os.environ['A2ALINK_BOOT_ARGS']);"
           "sys.exit(main())"]
    env = dict(os.environ)
    env["A2ALINK_BOOT_ARGS"] = json.dumps(boot_args, ensure_ascii=False)
    # 子进程必须能 import 到 a2alink——源码运行时 PYTHONPATH 可能是父进程
    # 临时设的，不能指望它已经写进环境。显式补上包所在的父目录。
    pkg_parent = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    env["PYTHONPATH"] = pkg_parent + (
        os.pathsep + env["PYTHONPATH"] if env.get("PYTHONPATH") else "")
    env["A2ALINK_QUIET"] = "1"

    kwargs: Dict[str, Any] = {
        "stdout": open(logf, "ab"),
        "stderr": subprocess.STDOUT,
        "stdin": subprocess.DEVNULL,
        "env": env,
        "cwd": root,
        "close_fds": True,
    }
    if os.name == "nt":
        # DETACHED_PROCESS：中继不能因为发起它的那个 CLI 退出而跟着死。
        # 否则发完第一条消息，中继就没了，第二条命令要再拉一次，无限循环。
        kwargs["creationflags"] = (subprocess.DETACHED_PROCESS
                                   | subprocess.CREATE_NEW_PROCESS_GROUP)
    else:
        kwargs["start_new_session"] = True

    try:
        proc = subprocess.Popen(cmd, **kwargs)
    except OSError as e:
        raise AutoStartError(f"无法启动本地中继: {e}") from e
    finally:
        try:
            kwargs["stdout"].close()        # type: ignore[union-attr]
        except Exception:
            pass

    with open(_pid_path(port), "w", encoding="utf-8") as f:
        json.dump({"pid": proc.pid, "port": port, "db": db,
                   "url": f"http://127.0.0.1:{port}",
                   "started_at": time.time()}, f, ensure_ascii=False)

    deadline = time.time() + timeout
    while time.time() < deadline:
        if probe(url) is not None:
            if not quiet:
                print(f"[a2alink] 本地中继已启动 pid={proc.pid} "
                      f"{url}  日志 {logf}")
            return {"managed": True, "started": True, "url": url,
                    "alive": True, "pid": proc.pid, "log": logf}
        if proc.poll() is not None:
            break
        time.sleep(0.12)

    tail = _tail(logf)
    raise AutoStartError(
        f"本地中继启动失败（{timeout:.0f}s 内 /healthz 未就绪）。\n"
        f"日志：{logf}\n{('- ' * 20)}\n{tail}")


def stop(url: str, quiet: bool = False) -> Dict[str, Any]:
    """停掉由本工具拉起来的中继。

    只认 pid 文件里的 pid。端口活着但没有 pid 文件 → 那是别人起的，不碰。
    """
    host, port, local = split_registry(url)
    if not local:
        return {"stopped": False, "reason": "remote"}

    info = read_pid(port)
    alive = probe(url) is not None
    if not alive:
        if info:
            try:
                os.remove(_pid_path(port))
            except OSError:
                pass
        return {"stopped": False, "reason": "not_running"}

    if not info:
        return {"stopped": False, "reason": "not_managed",
                "hint": "端口上有 a2alink，但不是本工具拉起的；请手动停止它。"}

    pid = int(info.get("pid") or 0)
    if pid <= 0:
        return {"stopped": False, "reason": "bad_pid_file"}

    try:
        os.kill(pid, 15)
    except OSError as e:
        return {"stopped": False, "reason": f"kill_failed: {e}", "pid": pid}

    deadline = time.time() + 5.0
    while time.time() < deadline:
        if not _port_open(host, port):
            break
        time.sleep(0.1)

    try:
        os.remove(_pid_path(port))
    except OSError:
        pass
    if not quiet:
        print(f"[a2alink] 已停止本地中继 pid={pid}")
    return {"stopped": True, "pid": pid}
