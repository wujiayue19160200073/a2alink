"""A2A Link —— 对端公钥固定（TOFU + pin）。

========================= 为什么需要这一层 =========================
只做签名验证是**不安全**的。考虑这个攻击：

  1. 注册中心（或任何能改 discover 响应的人）拿到 bob 的 agent_id
  2. 自己生成一对密钥，用私钥签一条"来自 bob"的消息
  3. 把这条消息和**自己的公钥**一起投递给你
  4. 你验签——通过。因为签名与公钥自洽，攻击者当然自洽。

所以"验签通过"只能证明"这条消息是持有对应私钥的人发的"，
**不能证明"这个私钥属于 bob"**。后者必须靠公钥固定：

  第一次见到 bob 的公钥 → 记下指纹（TOFU，trust on first use）
  以后再见到 bob → 指纹必须一致，不一致就报警并拒绝

这是 SSH 的 known_hosts 模型，也是唯一在不引入 CA 的前提下
能挡住"中间人换钥匙"的办法。它的代价是**首次见面无法防中间人**，
所以首次见面的指纹应该带外核对（电话、面对面、另一个可信信道）。

========================= 三种策略 =========================
  tofu    首次自动记录，指纹变化时拒绝并审计。（默认，适合开发）
  strict  没有本地记录就拒绝。适合生产：指纹先由人分发下去。
  off     不校验。只在你明确知道自己在做什么时使用——等于放弃防冒充。

指纹变化**一律不自动接受**。要更新必须显式 reset + 重新 pin，
并且会在变更历史里留下记录——"谁在什么时候把哪把钥匙换成了哪把"，
这件事本身就是要能查的。
"""

from __future__ import annotations

import json
import os
import time
from typing import Any, Dict, List, Optional

from .crypto import CryptoError, fingerprint_of

__all__ = ["TrustStore", "TrustDecision", "POLICY_TOFU", "POLICY_STRICT", "POLICY_OFF"]

POLICY_TOFU = "tofu"
POLICY_STRICT = "strict"
POLICY_OFF = "off"
POLICIES = (POLICY_TOFU, POLICY_STRICT, POLICY_OFF)


class TrustDecision(str):
    """信任判定结果。用 str 子类是为了能直接写进审计的 detail（JSON 友好）。"""


NEW = "new"            # 首次见到，已记录（tofu）
MATCH = "match"        # 与本地记录一致
MISMATCH = "mismatch"  # 与本地记录不一致 → 必须拒绝
UNKNOWN = "unknown"    # strict 模式下没有记录 → 必须拒绝
SKIPPED = "skipped"    # policy=off


class TrustStore:
    """对端公钥固定表，落在 <home>/trust/known_peers.json。

    单独一个文件而不是塞进 identity.json：因为它的生命周期不同——
    身份丢了可以重建，但"我信任过谁"这件事丢了，历史消息的可信度就没法回溯了。
    """

    def __init__(self, root: str, policy: str = POLICY_TOFU) -> None:
        if policy not in POLICIES:
            raise CryptoError(f"未知的信任策略: {policy!r}（可选 {POLICIES}）")
        self.root = root
        self.policy = policy
        self.path = os.path.join(root, "known_peers.json")
        self._data: Dict[str, Dict[str, Any]] = {}
        os.makedirs(root, exist_ok=True)
        self._load()

    # ---------------- 读写 ----------------
    def _load(self) -> None:
        if not os.path.exists(self.path):
            self._data = {}
            return
        try:
            with open(self.path, "r", encoding="utf-8") as f:
                d = json.load(f)
            if isinstance(d, dict) and isinstance(d.get("peers"), dict):
                self._data = d["peers"]
            else:
                self._data = {}
        except (OSError, json.JSONDecodeError):
            # 文件损坏时不要静默重建——那样等于把所有 pin 悄悄清空，
            # 下一次就能被换钥匙而不报警。宁可让上层看到异常。
            raise CryptoError(
                f"公钥固定文件损坏: {self.path}。请人工检查后再启动，"
                "不要直接删除（删除等于放弃对已有对端的防冒充能力）")

    def _save(self) -> None:
        tmp = self.path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump({"version": 1, "policy": self.policy, "peers": self._data},
                      f, ensure_ascii=False, indent=2, sort_keys=True)
        try:
            os.chmod(tmp, 0o600)
        except OSError:
            pass
        os.replace(tmp, self.path)

    # ---------------- 判定 ----------------
    def check(self, agent_id: str, sign_pub: bytes,
              kex_pub: Optional[bytes] = None) -> Dict[str, Any]:
        """判定这个 agent_id 当前的公钥是否可信。返回判定详情，不做 IO 审计。

        调用方拿到 decision 后必须：mismatch/unknown → 拒绝处理这条消息。
        """
        fp = fingerprint_of(sign_pub)
        kfp = fingerprint_of(kex_pub) if kex_pub else ""
        rec = self._data.get(agent_id)

        if self.policy == POLICY_OFF:
            return {"decision": SKIPPED, "agent_id": agent_id, "fp": fp,
                    "kex_fp": kfp, "detail": "policy=off，未做公钥固定校验"}

        if rec is None:
            if self.policy == POLICY_STRICT:
                return {"decision": UNKNOWN, "agent_id": agent_id, "fp": fp,
                        "kex_fp": kfp,
                        "detail": "strict 模式下没有本地记录，拒绝。"
                                  "先用 a2alink keys pin 手工导入对方指纹"}
            now = time.time()
            self._data[agent_id] = {
                "sign_fp": fp, "kex_fp": kfp,
                "sign_pub": sign_pub.hex(),
                "kex_pub": kex_pub.hex() if kex_pub else "",
                "first_seen": now, "last_seen": now, "source": "tofu",
                "seen_count": 1, "changes": [],
            }
            self._save()
            return {"decision": NEW, "agent_id": agent_id, "fp": fp, "kex_fp": kfp,
                    "detail": "首次见到该公钥，已记录（TOFU）。"
                              "首次见面的指纹未经带外核对，不能防中间人"}

        old_fp = rec.get("sign_fp", "")
        if old_fp == fp:
            rec["last_seen"] = time.time()
            rec["seen_count"] = int(rec.get("seen_count", 0)) + 1
            if kfp:
                rec["kex_fp"] = kfp
                rec["kex_pub"] = kex_pub.hex() if kex_pub else rec.get("kex_pub", "")
            self._save()
            return {"decision": MATCH, "agent_id": agent_id, "fp": fp, "kex_fp": kfp,
                    "detail": "与本地固定值一致"}

        # 指纹变了 —— 不自动接受
        return {"decision": MISMATCH, "agent_id": agent_id, "fp": fp,
                "kex_fp": kfp, "old_fp": old_fp,
                "detail": f"公钥变了（原 {old_fp}，今 {fp}）。"
                          "对方换机器是真的，有人在冒充也是真的，本工具不替你判断。"
                          "带外确认后用 a2alink keys repin 显式更新"}

    def record_mismatch(self, agent_id: str, fp: str,
                        action: str = "rejected") -> None:
        """把"发生过指纹不一致"记进变更历史。哪怕最后拒绝了，这条也要留。"""
        rec = self._data.get(agent_id)
        if not rec:
            return
        rec.setdefault("changes", []).append(
            {"at": time.time(), "old_fp": rec.get("sign_fp", ""),
             "new_fp": fp, "action": action})
        self._save()

    # ---------------- 人工操作 ----------------
    def pin(self, agent_id: str, sign_pub: bytes, kex_pub: Optional[bytes] = None,
            source: str = "manual", note: str = "") -> Dict[str, Any]:
        """手工固定（或覆盖）某个对端的公钥。source 会记进历史。"""
        fp = fingerprint_of(sign_pub)
        kfp = fingerprint_of(kex_pub) if kex_pub else ""
        old = self._data.get(agent_id, {})
        now = time.time()
        changes: List[Dict[str, Any]] = list(old.get("changes", []))
        if old and old.get("sign_fp") != fp:
            changes.append({"at": now, "old_fp": old.get("sign_fp", ""),
                            "new_fp": fp, "action": "repinned_by_operator",
                            "note": note})
        self._data[agent_id] = {
            "sign_fp": fp, "kex_fp": kfp,
            "sign_pub": sign_pub.hex(),
            "kex_pub": kex_pub.hex() if kex_pub else "",
            "first_seen": old.get("first_seen", now), "last_seen": now,
            "source": source, "seen_count": int(old.get("seen_count", 0)),
            "changes": changes,
        }
        self._save()
        return {"agent_id": agent_id, "fp": fp, "kex_fp": kfp,
                "replaced": bool(old and old.get("sign_fp") != fp)}

    def forget(self, agent_id: str) -> bool:
        """删除一条固定记录。下次见面会重新走过 TOFU 流程。

        ⚠️ 这等于放弃对这个对端的防冒充能力，直到你重新核对指纹。
        """
        if agent_id in self._data:
            del self._data[agent_id]
            self._save()
            return True
        return False

    def get(self, agent_id: str) -> Optional[Dict[str, Any]]:
        rec = self._data.get(agent_id)
        if not rec:
            return None
        return {k: v for k, v in rec.items() if not k.endswith("_pub")} | {
            "sign_pub_b64": _hex_to_b64(rec.get("sign_pub", "")),
            "kex_pub_b64": _hex_to_b64(rec.get("kex_pub", "")),
        }

    def known_kex_pub(self, agent_id: str) -> Optional[bytes]:
        """拿本地固定的交换公钥。发加密消息时优先用它而不是注册中心给的那份。"""
        rec = self._data.get(agent_id)
        if not rec or not rec.get("kex_pub"):
            return None
        try:
            b = bytes.fromhex(rec["kex_pub"])
        except ValueError:
            return None
        return b if len(b) == 32 else None

    def list(self) -> List[Dict[str, Any]]:
        out = []
        for aid, rec in sorted(self._data.items(),
                               key=lambda kv: -float(kv[1].get("last_seen", 0))):
            d = {k: v for k, v in rec.items() if not k.endswith("_pub")}
            d["agent_id"] = aid
            out.append(d)
        return out


def _hex_to_b64(h: str) -> str:
    if not h:
        return ""
    try:
        import base64
        return base64.b64encode(bytes.fromhex(h)).decode("ascii")
    except ValueError:
        return ""
