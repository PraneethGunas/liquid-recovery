"""
BIP32 HD Key Derivation using coincurve (libsecp256k1) for performance.
Falls back to ecdsa if coincurve is unavailable.
"""

import hashlib
import hmac
import struct

SECP256K1_ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

# Try fast C library first, fall back to pure Python
try:
    from coincurve import PublicKey as _CPublicKey

    def _get_pubkey(privkey_bytes: bytes) -> bytes:
        pk = _CPublicKey.from_valid_secret(privkey_bytes)
        return pk.format(compressed=True)

    _ENGINE = "coincurve"
except ImportError:
    from ecdsa import SECP256k1, SigningKey

    def _get_pubkey(privkey_bytes: bytes) -> bytes:
        sk = SigningKey.from_string(privkey_bytes, curve=SECP256k1)
        vk = sk.get_verifying_key()
        x = vk.pubkey.point.x()
        y = vk.pubkey.point.y()
        prefix = b"\x02" if y % 2 == 0 else b"\x03"
        return prefix + x.to_bytes(32, "big")

    _ENGINE = "ecdsa"


def get_engine():
    return _ENGINE


def _hmac_sha512(key: bytes, data: bytes) -> bytes:
    return hmac.new(key, data, hashlib.sha512).digest()


class HDKey:
    """BIP32 Hierarchical Deterministic Key."""

    __slots__ = ("privkey", "chaincode", "_pubkey")

    def __init__(self, privkey: bytes, chaincode: bytes):
        self.privkey = privkey
        self.chaincode = chaincode
        self._pubkey = None

    @classmethod
    def from_seed(cls, seed: bytes) -> "HDKey":
        I = _hmac_sha512(b"Bitcoin seed", seed)
        return cls(I[:32], I[32:])

    @property
    def pubkey(self) -> bytes:
        if self._pubkey is None:
            self._pubkey = _get_pubkey(self.privkey)
        return self._pubkey

    def derive_child(self, index: int) -> "HDKey":
        if index >= 0x80000000:
            data = b"\x00" + self.privkey + struct.pack(">I", index)
        else:
            data = self.pubkey + struct.pack(">I", index)
        I = _hmac_sha512(self.chaincode, data)
        child_int = (
            int.from_bytes(I[:32], "big") + int.from_bytes(self.privkey, "big")
        ) % SECP256K1_ORDER
        return HDKey(child_int.to_bytes(32, "big"), I[32:])

    def derive_path(self, path: str) -> "HDKey":
        """Derive from path like m/84'/1776'/0'/0"""
        parts = path.strip().split("/")
        if parts[0] == "m":
            parts = parts[1:]
        key = self
        for part in parts:
            hardened = part.endswith(("'", "h", "H"))
            idx = int(part.rstrip("'hH"))
            if hardened:
                idx += 0x80000000
            key = key.derive_child(idx)
        return key
