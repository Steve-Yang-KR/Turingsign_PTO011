from pathlib import Path
from backend.security import KeyStore, generate_totp_secret, totp_now, verify_totp


def test_totp_roundtrip():
    s=generate_totp_secret(); assert verify_totp(s, totp_now(s))


def test_persistent_receipt_key(tmp_path: Path):
    k1=KeyStore(tmp_path); signed=k1.sign_receipt({"hello":"world"}); assert k1.verify_receipt(signed)
    k2=KeyStore(tmp_path); assert k2.verify_receipt(signed)


def test_vault_encrypt_decrypt(tmp_path: Path):
    k=KeyStore(tmp_path); enc=k.encrypt_vault({"x":1},"aad"); assert k.decrypt_vault(enc["nonce"],enc["ciphertext"],"aad")=={"x":1}
