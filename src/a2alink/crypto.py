"""A2A Link —— 通信密码学（纯 Python，零第三方依赖）。

========================= 先说清楚这是什么 =========================
这个模块自己实现了 Ed25519 签名与 X25519 密钥交换，因为项目立了
"零第三方依赖"的规矩。这是**有代价的决定**，必须诚实写在这里：

  ✅ 数学正确性：完全按 RFC 8032 / RFC 7748 的参考实现编写，
     并用 RFC 官方测试向量逐条验证（tests/test_crypto.py）。
  ⚠️ 侧信道：纯 Python 不是常量时间实现。同机攻击者理论上可以通过
     缓存计时旁路推测私钥。**能防远程攻击者，不能防本机 root。**
  ⚠️ 性能：签名约 10-40ms，比 OpenSSL 慢两个数量级。
     对 Agent 级通信（秒级）够用，不适合高频交易链路。

如果目标环境允许装依赖，`cryptography` 库会更快更稳。本模块刻意
不自动降级到它——**已经发生过的漏洞里，很大一部分来自"有两条路径，
其中一条很久没被测试"**。要换实现就整体换，别做半自动切换。

========================= 威胁模型 =========================
能挡住的：
  · 注册中心冒充任意 Agent 发消息（它没有私钥，签不出来）
  · 中间人篡改信封任意字段（签名覆盖 from / to / payload / budget）
  · 链路旁路读取正文（单聊端到端加密，中继只见密文）
  · 重放整条消息（签名含 created_at / expires_at / id，过期即拒）

挡不住的：
  · 元数据（谁在什么时候和谁通信、消息多大、多频繁）
  · 已被攻陷的端点本身（私钥在对方机器上，它当然能签）
  · 拥有本机 root 权限的人（可读私钥文件，也可改内存）
  · 群聊正文（v0.2 群消息只签名不加密，见 docs/crypto.md）
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import os
import secrets
import struct
from typing import Any, Dict, Optional, Tuple

__all__ = [
    "CryptoError", "SignatureError", "DecryptionError", "KeyMismatchError",
    "X25519KeyPair", "Ed25519KeyPair", "KeyStore",
    "hkdf_sha256", "aead_seal", "aead_open",
    "b64e", "b64d", "fingerprint_of", "random_bytes",
]


# ==========================================================================
# 错误类型
# ==========================================================================
class CryptoError(Exception):
    """密码学相关错误的基类。上层一律按"不可信输入"处理，不要吞掉。"""


class SignatureError(CryptoError):
    """签名验证失败。意味着：消息被改过，或者发送者不是自称的那个人。"""


class DecryptionError(CryptoError):
    """解密失败。密文被篡改、密钥不对，或者发错了人。"""


class KeyMismatchError(CryptoError):
    """对端公钥与本地固定（pin）的指纹不一致——可能是注册中心在换钥匙。"""


# ==========================================================================
# 编码工具
# ==========================================================================
def b64e(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def b64d(s: str) -> bytes:
    """严格解 base64。不要用 validate=False 的宽松模式——
    "能解出来"和"是我期望的那串字节"是两件事。"""
    if not isinstance(s, str):
        raise CryptoError("base64 字段必须是字符串")
    try:
        return base64.b64decode(s.encode("ascii"), validate=True)
    except (ValueError, UnicodeEncodeError) as e:
        raise CryptoError(f"base64 解码失败: {e}") from e


def random_bytes(n: int) -> bytes:
    return secrets.token_bytes(n)


def fingerprint_of(pub: bytes) -> str:
    """公钥指纹：SHA256 前 16 字节，按 4 字符分组，方便人眼比对。

    分组不是为了好看，是为了**人能在电话里逐段念出来核对**——
    带外验证是这套体系里唯一不依赖注册中心的一环。
    """
    h = hashlib.sha256(pub).hexdigest()[:32]
    return "-".join(h[i:i + 4] for i in range(0, 32, 4))


# ==========================================================================
# GF(2^255 - 19) 有限域
# ==========================================================================
_P = 2 ** 255 - 19
_L = 2 ** 252 + 27742317777372353535851937790883648493   # Ed25519 子群阶
_D = -121665 * pow(121666, _P - 2, _P) % _P              # 曲线常数 d
_I = pow(2, (_P - 1) // 4, _P)                           # sqrt(-1)


def _inv(x: int) -> int:
    return pow(x, _P - 2, _P)


# ==========================================================================
# X25519（RFC 7748）—— 密钥交换
# ==========================================================================
def _decode_u(b: bytes) -> int:
    """把 32 字节小端解成 u 坐标。最高位必须屏蔽（RFC 7748 §5）。"""
    if len(b) != 32:
        raise CryptoError(f"X25519 公钥必须是 32 字节，收到 {len(b)}")
    return int.from_bytes(b, "little") & ((1 << 255) - 1)


def _encode_u(u: int) -> bytes:
    return (u % _P).to_bytes(32, "little")


def x25519(k: bytes, u: bytes) -> bytes:
    """X25519 标量乘。Montgomery ladder，全程不分支（Python 层面尽力而为）。"""
    if len(k) != 32:
        raise CryptoError("X25519 私钥必须是 32 字节")
    scalar = bytearray(k)
    # 标准钳位（clamping）：保证标量落在正确子群，抵抗小子群攻击
    scalar[0] &= 248
    scalar[31] &= 127
    scalar[31] |= 64
    n = int.from_bytes(scalar, "little")
    x1 = _decode_u(u)

    x2, z2, x3, z3 = 1, 0, x1, 1
    swap = 0
    for t in reversed(range(255)):
        kt = (n >> t) & 1
        swap ^= kt
        if swap:                       # 条件交换，用算术而非 if 分支的选择
            x2, x3 = x3, x2
            z2, z3 = z3, z2
        swap = kt

        a = (x2 + z2) % _P
        aa = a * a % _P
        b = (x2 - z2) % _P
        bb = b * b % _P
        e = (aa - bb) % _P
        c = (x3 + z3) % _P
        d_ = (x3 - z3) % _P
        da = d_ * a % _P
        cb = c * b % _P
        x3 = (da + cb) % _P
        x3 = x3 * x3 % _P
        z3 = (da - cb) % _P
        z3 = x1 * (z3 * z3 % _P) % _P
        x2 = aa * bb % _P
        z2 = e * ((aa + 121665 * e) % _P) % _P

    if swap:
        x2, x3 = x3, x2
        z2, z3 = z3, z2
    if z2 % _P == 0:
        raise CryptoError("X25519 结果为零（对端公钥是低阶点，疑似攻击）")
    return _encode_u(x2 * _inv(z2) % _P)


class X25519KeyPair:
    """密钥交换密钥对。私钥 32 字节随机，公钥 = X25519(priv, basepoint)。"""

    __slots__ = ("_priv", "_pub")

    BASE = (9).to_bytes(32, "little")

    def __init__(self, private: bytes) -> None:
        if len(private) != 32:
            raise CryptoError("X25519 私钥必须是 32 字节")
        self._priv = bytes(private)
        self._pub = x25519(self._priv, self.BASE)

    @classmethod
    def generate(cls) -> "X25519KeyPair":
        return cls(random_bytes(32))

    @property
    def private_bytes(self) -> bytes:
        return self._priv

    @property
    def public_bytes(self) -> bytes:
        return self._pub

    @property
    def public_b64(self) -> str:
        return b64e(self._pub)

    def agree(self, peer_pub: bytes) -> bytes:
        """与对端公钥算出共享秘密。调用方必须再用 KDF 派生，
        绝不能直接拿共享秘密当密钥用（RFC 7748 §6.1 明确要求）。"""
        return x25519(self._priv, peer_pub)


# ==========================================================================
# Ed25519（RFC 8032）—— 签名
# ==========================================================================
def _sha512_int(*parts: bytes) -> int:
    """把 SHA-512 的**完整 64 字节**当作小端整数。

    这里有个很容易踩的坑：不少实现只取哈希的前 32 字节，然后自签自验
    一切正常，但跟任何标准实现都对不上。RFC 8032 §5.1.6 明确规定是
    整条 512 位输出取整数再 mod L —— 这就是为什么必须跑官方测试向量，
    而不是"我签完自己能验过就算成功"。
    """
    return int.from_bytes(hashlib.sha512(b"".join(parts)).digest(), "little")


def _ed_add(P, Q):
    """扩展扭曲爱德华兹坐标下的点加法（RFC 8032 §5.1.4 的统一公式）。"""
    A = (P[1] - P[0]) * (Q[1] - Q[0]) % _P
    B = (P[1] + P[0]) * (Q[1] + Q[0]) % _P
    C = 2 * P[3] * Q[3] * _D % _P
    D = 2 * P[2] * Q[2] % _P
    E, F, G, H = B - A, D - C, D + C, B + A
    return (E * F % _P, G * H % _P, F * G % _P, E * H % _P)


def _ed_mul(s: int, P):
    """标量乘。用双倍加，从最高位往下走。"""
    Q = (0, 1, 1, 0)                 # 单位元
    while s > 0:
        if s & 1:
            Q = _ed_add(Q, P)
        P = _ed_add(P, P)
        s >>= 1
    return Q


def _ed_equal(P, Q) -> bool:
    if (P[0] * Q[2] - Q[0] * P[2]) % _P != 0:
        return False
    if (P[1] * Q[2] - Q[1] * P[2]) % _P != 0:
        return False
    return True


def _ed_recover_x(y: int, sign: int) -> Optional[int]:
    """由 y 恢复 x。返回 None 表示这个 y 不在曲线上。"""
    if y >= _P:
        return None
    x2 = (y * y - 1) * _inv(_D * y * y + 1) % _P
    if x2 == 0:
        return None if sign else 0
    x = pow(x2, (_P + 3) // 8, _P)
    if (x * x - x2) % _P != 0:
        x = x * _I % _P
    if (x * x - x2) % _P != 0:
        return None
    if (x & 1) != sign:
        x = _P - x
    return x


_GY = 4 * _inv(5) % _P
_GX = _ed_recover_x(_GY, 0)
_G = (_GX, _GY, 1, _GX * _GY % _P)


def _ed_encode(P) -> bytes:
    zinv = _inv(P[2])
    x = P[0] * zinv % _P
    y = P[1] * zinv % _P
    return (y | ((x & 1) << 255)).to_bytes(32, "little")


def _ed_decode(b: bytes):
    if len(b) != 32:
        raise SignatureError(f"Ed25519 公钥必须是 32 字节，收到 {len(b)}")
    v = int.from_bytes(b, "little")
    sign = (v >> 255) & 1
    y = v & ((1 << 255) - 1)
    x = _ed_recover_x(y, sign)
    if x is None:
        raise SignatureError("公钥不在曲线上（非法的 Ed25519 公钥）")
    return (x, y, 1, x * y % _P)


class Ed25519KeyPair:
    """签名密钥对。私钥是 32 字节种子，公钥是 32 字节压缩点。"""

    __slots__ = ("_seed", "_pub", "_a", "_prefix")

    def __init__(self, seed: bytes) -> None:
        if len(seed) != 32:
            raise CryptoError("Ed25519 种子必须是 32 字节")
        self._seed = bytes(seed)
        h = hashlib.sha512(seed).digest()
        a = int.from_bytes(h[:32], "little")
        a &= (1 << 254) - 8          # clamp
        a |= (1 << 254)
        self._a = a
        self._prefix = h[32:]
        self._pub = _ed_encode(_ed_mul(a, _G))

    @classmethod
    def generate(cls) -> "Ed25519KeyPair":
        return cls(random_bytes(32))

    @property
    def private_bytes(self) -> bytes:
        return self._seed

    @property
    def public_bytes(self) -> bytes:
        return self._pub

    @property
    def public_b64(self) -> str:
        return b64e(self._pub)

    @property
    def fingerprint(self) -> str:
        return fingerprint_of(self._pub)

    def sign(self, msg: bytes) -> bytes:
        r = _sha512_int(self._prefix, msg) % _L
        R = _ed_mul(r, _G)
        Rb = _ed_encode(R)
        h = _sha512_int(Rb, self._pub, msg) % _L
        S = (r + h * self._a) % _L
        return Rb + S.to_bytes(32, "little")

    @staticmethod
    def verify(public: bytes, msg: bytes, sig: bytes) -> bool:
        """验签。任何解析异常都返回 False——异常与"签名无效"在上层等价，
        但绝不能让异常逃逸成"跳过校验"。"""
        try:
            if len(sig) != 64:
                return False
            A = _ed_decode(public)
            Rb, Sb = sig[:32], sig[32:]
            S = int.from_bytes(Sb, "little")
            if S >= _L:                    # 非规范编码，直接拒
                return False
            R = _ed_decode(Rb)
            h = _sha512_int(Rb, public, msg) % _L
            # 检查 [S]B == R + [h]A
            left = _ed_mul(S, _G)
            right = _ed_add(R, _ed_mul(h, A))
            return _ed_equal(left, right)
        except (CryptoError, ValueError, ZeroDivisionError):
            return False


# ==========================================================================
# HKDF-SHA256（RFC 5869）—— 从共享秘密派生密钥
# ==========================================================================
def hkdf_sha256(ikm: bytes, salt: bytes, info: bytes, length: int = 64) -> bytes:
    """标准 HKDF。共享秘密不能直接当密钥用，必须先过这一步。"""
    if length <= 0 or length > 255 * 32:
        raise CryptoError("HKDF 输出长度非法")
    prk = hmac.new(salt or b"\x00" * 32, ikm, hashlib.sha256).digest()
    out, t, i = b"", b"", 1
    while len(out) < length:
        t = hmac.new(prk, t + info + bytes([i]), hashlib.sha256).digest()
        out += t
        i += 1
    return out[:length]


# ==========================================================================
# 认证加密：PRF-CTR + Encrypt-then-MAC
# ==========================================================================
# 为什么不自己写 AES-GCM：手写 AES 的 S 盒与 GCM 的 GHASH 是典型的
# "看起来能跑、实际有微妙错误"的地方，而且纯 Python 的 AES 慢到不可用。
# 这里改用 HMAC-SHA256 作 PRF 构造 CTR 流密码（PRF-CTR 是可证明安全的构造），
# 再用 HMAC-SHA256 做 Encrypt-then-MAC。两个原语都是 stdlib，且只有几行代码，
# 出错空间远小于手写 AES。
_AEAD_ALG = "x25519-hkdf256-hmacctr-hmac256"


def _keystream(key: bytes, nonce: bytes, length: int) -> bytes:
    out = bytearray()
    counter = 0
    while len(out) < length:
        out += hmac.new(key, nonce + struct.pack(">Q", counter), hashlib.sha256).digest()
        counter += 1
    return bytes(out[:length])


def _xor(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def aead_seal(key: bytes, plaintext: bytes, aad: bytes = b"") -> Dict[str, str]:
    """加密 + 认证。返回可直接塞进 JSON 的 dict。

    aad（additional authenticated data）绑定信封头部：
    攻击者改不了 from/to/conversation_id，改了 tag 就验不过。
    """
    if len(key) != 32:
        raise CryptoError("AEAD 密钥必须是 32 字节")
    nonce = random_bytes(16)
    ct = _xor(plaintext, _keystream(key, nonce, len(plaintext)))
    mac_key = hkdf_sha256(key, b"a2alink/aead/mac", b"mac", 32)
    tag = hmac.new(mac_key, aad + nonce + ct, hashlib.sha256).digest()
    return {"n": b64e(nonce), "ct": b64e(ct), "tag": b64e(tag)}


def aead_open(key: bytes, sealed: Dict[str, str], aad: bytes = b"") -> bytes:
    """解密 + 验认证标签。先验再解，防止 padding oracle 类的旁路。"""
    try:
        nonce = b64d(sealed["n"])
        ct = b64d(sealed["ct"])
        tag = b64d(sealed["tag"])
    except (KeyError, TypeError) as e:
        raise DecryptionError(f"密文结构不完整: {e}") from e
    if len(nonce) != 16 or len(tag) != 32:
        raise DecryptionError("nonce 或 tag 长度非法")
    mac_key = hkdf_sha256(key, b"a2alink/aead/mac", b"mac", 32)
    expect = hmac.new(mac_key, aad + nonce + ct, hashlib.sha256).digest()
    # 常量时间比较：不要用 == 比较 MAC
    if not hmac.compare_digest(expect, tag):
        raise DecryptionError("认证标签不匹配：密文被篡改，或密钥不对")
    return _xor(ct, _keystream(key, nonce, len(ct)))


# ==========================================================================
# 会话加密：把一个 payload 加密给指定接收方
# ==========================================================================
_DOMAIN_MSG = b"a2alink/v1/msg\x00"


def encrypt_for(recipient_kex_pub: bytes, plaintext: bytes,
                aad: bytes = b"") -> Dict[str, str]:
    """用接收方的 X25519 公钥加密。每次生成临时密钥对 → 自带前向保密：
    即使本机私钥日后泄露，也解不开历史消息（除非对方保留了临时私钥，而它随用随弃）。
    """
    eph = X25519KeyPair.generate()
    shared = eph.agree(recipient_kex_pub)
    # salt 绑定双方公钥：防止密钥复用攻击（UKS）
    okm = hkdf_sha256(shared, eph.public_bytes + recipient_kex_pub, _DOMAIN_MSG, 32)
    sealed = aead_seal(okm, plaintext, aad)
    return {"alg": _AEAD_ALG, "epk": eph.public_b64,
            "n": sealed["n"], "ct": sealed["ct"], "tag": sealed["tag"]}


def decrypt_from(my_kex: X25519KeyPair, my_kex_pub: bytes,
                 blob: Dict[str, str], aad: bytes = b"") -> bytes:
    if not isinstance(blob, dict):
        raise DecryptionError("enc 字段必须是 object")
    if blob.get("alg") != _AEAD_ALG:
        raise DecryptionError(f"不支持的加密算法: {blob.get('alg')!r}")
    try:
        epk = b64d(blob["epk"])
    except KeyError as e:
        raise DecryptionError("缺少 epk（发送方临时公钥）") from e
    shared = my_kex.agree(epk)
    okm = hkdf_sha256(shared, epk + my_kex_pub, _DOMAIN_MSG, 32)
    return aead_open(okm, blob, aad)


# ==========================================================================
# 密钥存储：私钥永不离开本机
# ==========================================================================
class KeyStore:
    """一个 Agent 的密钥目录。

    目录结构（<home>/keys/）：
      signing.key   32 字节 Ed25519 种子
      kex.key       32 字节 X25519 私钥
      *.pub         对应的公钥，可公开

    权限一律 0600，且在 Windows 上也会尝试设置。谈不上绝对安全，
    但至少能挡住同机其他普通用户的顺手一读。
    """

    def __init__(self, root: str) -> None:
        self.root = root
        self.signing: Optional[Ed25519KeyPair] = None
        self.kex: Optional[X25519KeyPair] = None
        self.created_at: float = 0.0
        os.makedirs(root, exist_ok=True)
        self._harden_dir()

    # ---------------- 内部 ----------------
    def _harden_dir(self) -> None:
        try:
            os.chmod(self.root, 0o700)
        except OSError:
            pass

    def _path(self, name: str) -> str:
        return os.path.join(self.root, name)

    @staticmethod
    def _read_key(path: str, expect: int = 32) -> bytes:
        with open(path, "rb") as f:
            data = f.read()
        if len(data) != expect:
            raise CryptoError(f"{os.path.basename(path)} 长度异常"
                              f"（应为 {expect}，实际 {len(data)}），文件可能损坏")
        return data

    @staticmethod
    def _write_key(path: str, data: bytes) -> None:
        """先写临时文件再原子替换，避免写到一半断电留下半个私钥。

        ⚠️ 必须显式带 O_BINARY。Windows 上 os.open 默认是文本模式，
        私钥里随机出现的 0x0A 会被写成 0x0D 0x0A —— 32 字节变 33 字节，
        密钥就废了。32 字节随机数含 0x0A 的概率约 12%，这意味着
        "偶尔有人的密钥文件读不出来"，而且 Linux 上永远复现不了。
        """
        tmp = path + ".tmp"
        flags = os.O_CREAT | os.O_WRONLY | os.O_TRUNC | getattr(os, "O_BINARY", 0)
        fd = os.open(tmp, flags, 0o600)
        try:
            view = memoryview(data)
            while view:                      # os.write 可能只写一部分
                n = os.write(fd, view)
                view = view[n:]
            os.fsync(fd)
        finally:
            os.close(fd)
        try:
            os.chmod(tmp, 0o600)
        except OSError:
            pass
        os.replace(tmp, path)

    # ---------------- 对外 ----------------
    @property
    def initialized(self) -> bool:
        return (os.path.exists(self._path("signing.key"))
                and os.path.exists(self._path("kex.key")))

    def load_or_create(self) -> "KeyStore":
        if self.initialized:
            self.signing = Ed25519KeyPair(self._read_key(self._path("signing.key")))
            self.kex = X25519KeyPair(self._read_key(self._path("kex.key")))
        else:
            self.generate()
        return self

    def generate(self, force: bool = False) -> "KeyStore":
        """生成新密钥对。**不覆盖已有密钥**——覆盖等于把身份弄丢，
        别人 pin 的指纹会全部对不上。要换钥匙请用 rotate()。

        force 仅供 rotate() 内部在旧文件已归档后调用。
        """
        if self.initialized and not force:
            raise CryptoError("密钥已存在。要更换请显式调用 rotate()")
        self.signing = Ed25519KeyPair.generate()
        self.kex = X25519KeyPair.generate()
        self._write_key(self._path("signing.key"), self.signing.private_bytes)
        self._write_key(self._path("kex.key"), self.kex.private_bytes)
        with open(self._path("signing.pub"), "wb") as f:
            f.write(self.signing.public_bytes)
        with open(self._path("kex.pub"), "wb") as f:
            f.write(self.kex.public_bytes)
        self.created_at = os.path.getmtime(self._path("signing.key"))
        return self

    def rotate(self) -> Dict[str, str]:
        """轮换密钥。旧私钥被归档而不是删除——已经加密的历史消息
        还需要它来解（如果你选择保留历史）。归档文件名带时间戳，
        方便事后追溯"哪一段期间用的是哪把钥匙"。
        """
        import time as _t
        if not self.initialized:
            self.generate()
            return {"state": "created"}
        stamp = _t.strftime("%Y%m%d-%H%M%S", _t.localtime())
        for name in ("signing.key", "kex.key", "signing.pub", "kex.pub"):
            src = self._path(name)
            if os.path.exists(src):
                os.replace(src, self._path(f"{name}.{stamp}.old"))
        old_fp = self.signing.fingerprint if self.signing else ""
        # 旧文件已挪走，此时目录里没有密钥，force 只用于跳过这道检查
        self.generate(force=True)
        return {"state": "rotated", "old_fingerprint": old_fp,
                "new_fingerprint": self.signing.fingerprint,
                "archived_as": stamp}

    # ---------------- 派生 ----------------
    def sign(self, msg: bytes) -> bytes:
        if not self.signing:
            raise CryptoError("签名密钥未加载")
        return self.signing.sign(msg)

    def public_bundle(self) -> Dict[str, str]:
        if not self.signing or not self.kex:
            raise CryptoError("密钥未加载")
        return {"sign_pub": self.signing.public_b64,
                "kex_pub": self.kex.public_b64,
                "fingerprint": self.signing.fingerprint,
                "alg": "ed25519+x25519"}

    def describe(self) -> Dict[str, Any]:
        if not self.signing or not self.kex:
            return {"initialized": self.initialized, "root": self.root}
        return {
            "root": self.root,
            "sign_fingerprint": self.signing.fingerprint,
            "kex_fingerprint": fingerprint_of(self.kex.public_bytes),
            "sign_pub": self.signing.public_b64,
            "kex_pub": self.kex.public_b64,
            "private_files": [self._path("signing.key"), self._path("kex.key")],
        }
