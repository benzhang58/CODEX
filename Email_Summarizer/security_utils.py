import base64
import hashlib
import json
import os
import secrets
from functools import lru_cache
from pathlib import Path
from typing import Any, Dict

from cryptography.fernet import Fernet


ENCRYPTED_PREFIX = "enc::"


def _derive_fernet_key(raw_secret: str) -> bytes:
    digest = hashlib.sha256(raw_secret.encode("utf-8")).digest()
    return base64.urlsafe_b64encode(digest)


@lru_cache(maxsize=8)
def get_fernet(storage_dir: str) -> Fernet:
    explicit_secret = os.getenv("EMAIL_SUMMARIZER_ENCRYPTION_KEY", "").strip()
    if explicit_secret:
        return Fernet(_derive_fernet_key(explicit_secret))

    app_dir = Path(storage_dir) / "app"
    app_dir.mkdir(parents=True, exist_ok=True)
    key_path = app_dir / "email_summarizer.key"
    if not key_path.exists():
        key_path.write_bytes(Fernet.generate_key())
        try:
            key_path.chmod(0o600)
        except OSError:
            pass
    return Fernet(key_path.read_bytes().strip())


def encrypt_json_payload(payload: Dict[str, Any], storage_dir: Path) -> str:
    token = get_fernet(str(storage_dir)).encrypt(
        json.dumps(payload, ensure_ascii=False).encode("utf-8")
    )
    return ENCRYPTED_PREFIX + token.decode("utf-8")


def decrypt_json_payload(raw_value: str, storage_dir: Path) -> Dict[str, Any]:
    value = str(raw_value or "").strip()
    if not value:
        return {}
    if value.startswith(ENCRYPTED_PREFIX):
        decrypted = get_fernet(str(storage_dir)).decrypt(
            value[len(ENCRYPTED_PREFIX):].encode("utf-8")
        )
        payload = json.loads(decrypted.decode("utf-8"))
        return payload if isinstance(payload, dict) else {}

    payload = json.loads(value)
    return payload if isinstance(payload, dict) else {}


def maybe_encrypt_legacy_json(raw_value: str, storage_dir: Path) -> str:
    value = str(raw_value or "").strip()
    if not value:
        return encrypt_json_payload({}, storage_dir)
    if value.startswith(ENCRYPTED_PREFIX):
        return value
    try:
        payload = json.loads(value)
    except json.JSONDecodeError:
        payload = {"value": value}
    if not isinstance(payload, dict):
        payload = {"value": payload}
    return encrypt_json_payload(payload, storage_dir)
