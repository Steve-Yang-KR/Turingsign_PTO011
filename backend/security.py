from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import struct
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def b64u_decode(data: str) -> bytes:
    return base64.urlsafe_b64decode(data + "=" * (-len(data) % 4))


def canonical_json(payload: Dict[str, Any]) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


class PasswordService:
    def __init__(self):
        self.ph = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=4)

    def hash(self, password: str, min_length: int = 12) -> str:
        if len(password) < min_length:
            raise ValueError(f"Alpha password must be at least {min_length} characters")
        return self.ph.hash(password)

    def verify(self, password_hash: str, password: str) -> bool:
        try:
            return self.ph.verify(password_hash, password)
        except VerifyMismatchError:
            return False


def generate_totp_secret() -> str:
    return base64.b32encode(os.urandom(20)).decode("ascii").rstrip("=")


def _totp_at(secret: str, counter: int, digits: int = 6) -> str:
    padded = secret + "=" * (-len(secret) % 8)
    key = base64.b32decode(padded, casefold=True)
    msg = struct.pack(">Q", counter)
    digest = hmac.new(key, msg, hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    code = (struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF) % (10 ** digits)
    return str(code).zfill(digits)


def totp_now(secret: str, period: int = 30) -> str:
    return _totp_at(secret, int(time.time()) // period)


def verify_totp(secret: str, code: str, window: int = 1, period: int = 30) -> bool:
    if not code or not code.isdigit():
        return False
    counter = int(time.time()) // period
    return any(hmac.compare_digest(_totp_at(secret, counter + delta), code) for delta in range(-window, window + 1))


def otpauth_uri(secret: str, account: str, issuer: str = "Turingsign PTO Alpha") -> str:
    from urllib.parse import quote
    return f"otpauth://totp/{quote(issuer)}:{quote(account)}?secret={secret}&issuer={quote(issuer)}&algorithm=SHA1&digits=6&period=30"


class KeyStore:
    """Persistent local Alpha keys. Replace with cloud KMS/HSM before production."""

    def __init__(self, data_dir: Path):
        self.data_dir = data_dir
        self.keys_dir = data_dir / "keys"
        self.keys_dir.mkdir(parents=True, exist_ok=True)
        self.receipt_key = self._load_or_create_ed25519("receipt_ed25519.pem")
        self.credential_key = self._load_or_create_ed25519("credential_ed25519.pem")
        self.vault_key = self._load_or_create_symmetric("vault_aes256.key", 32)
        self.session_secret = self._load_or_create_symmetric("session_secret.key", 32)

    def _load_or_create_ed25519(self, name: str) -> Ed25519PrivateKey:
        path = self.keys_dir / name
        if path.exists():
            return serialization.load_pem_private_key(path.read_bytes(), password=None)
        key = Ed25519PrivateKey.generate()
        raw = key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        path.write_bytes(raw)
        try:
            path.chmod(0o600)
        except OSError:
            pass
        return key

    def _load_or_create_symmetric(self, name: str, size: int) -> bytes:
        path = self.keys_dir / name
        if path.exists():
            return path.read_bytes()
        raw = secrets.token_bytes(size)
        path.write_bytes(raw)
        try:
            path.chmod(0o600)
        except OSError:
            pass
        return raw

    def public_receipt_key_b64(self) -> str:
        pub = self.receipt_key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        return b64u(pub)

    def sign_receipt(self, body: Dict[str, Any]) -> Dict[str, Any]:
        payload = dict(body)
        payload.setdefault("issued_at", utcnow())
        sig = self.receipt_key.sign(canonical_json(payload))
        return {
            "receipt": payload,
            "signature_alg": "Ed25519",
            "signature": b64u(sig),
            "public_key": self.public_receipt_key_b64(),
            "key_management": "persistent-local-alpha; replace with KMS/HSM before production",
        }

    def verify_receipt(self, signed: Dict[str, Any]) -> bool:
        try:
            pub = Ed25519PublicKey.from_public_bytes(b64u_decode(signed["public_key"]))
            pub.verify(b64u_decode(signed["signature"]), canonical_json(signed["receipt"]))
            return True
        except Exception:
            return False

    def issue_agent_token(self, payload: Dict[str, Any]) -> str:
        encoded = b64u(canonical_json(payload))
        sig = self.credential_key.sign(encoded.encode("ascii"))
        return f"{encoded}.{b64u(sig)}"

    def verify_agent_token(self, token: str) -> Dict[str, Any]:
        encoded, sig = token.split(".", 1)
        self.credential_key.public_key().verify(b64u_decode(sig), encoded.encode("ascii"))
        return json.loads(b64u_decode(encoded))

    def encrypt_vault(self, payload: Dict[str, Any], aad: str) -> Dict[str, str]:
        nonce = secrets.token_bytes(12)
        ciphertext = AESGCM(self.vault_key).encrypt(nonce, canonical_json(payload), aad.encode("utf-8"))
        return {"nonce": b64u(nonce), "ciphertext": b64u(ciphertext)}

    def decrypt_vault(self, nonce: str, ciphertext: str, aad: str) -> Dict[str, Any]:
        raw = AESGCM(self.vault_key).decrypt(b64u_decode(nonce), b64u_decode(ciphertext), aad.encode("utf-8"))
        return json.loads(raw)


class SessionService:
    def __init__(self, secret: bytes):
        self.serializer = URLSafeTimedSerializer(b64u(secret), salt="pto-alpha-session")

    def create(self, principal_id: str) -> str:
        return self.serializer.dumps({"principal_id": principal_id, "nonce": secrets.token_hex(8), "iat": utcnow()})

    def read(self, token: str, max_age: int = 8 * 3600) -> Optional[Dict[str, Any]]:
        try:
            return self.serializer.loads(token, max_age=max_age)
        except (BadSignature, SignatureExpired):
            return None
