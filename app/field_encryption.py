from __future__ import annotations

import base64
import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


FIELD_ENCRYPTION_KEY_ENV = "RD_KG_FIELD_ENCRYPTION_KEY"
FIELD_ENCRYPTION_PREFIX = "rdkg:v1:aesgcm:"


class FieldDecryptionError(ValueError):
    pass


def field_encryption_enabled() -> bool:
    return bool(os.getenv(FIELD_ENCRYPTION_KEY_ENV, "").strip())


def generate_field_encryption_key() -> str:
    return base64.urlsafe_b64encode(os.urandom(32)).decode("ascii")


def is_encrypted_value(value: str | None) -> bool:
    return bool(isinstance(value, str) and value.startswith(FIELD_ENCRYPTION_PREFIX))


def _field_key() -> bytes | None:
    key_value = os.getenv(FIELD_ENCRYPTION_KEY_ENV, "").strip()
    if not key_value:
        return None
    try:
        raw = base64.urlsafe_b64decode(key_value.encode("ascii"))
    except Exception as exc:  # noqa: BLE001 - normalize configuration error
        raise FieldDecryptionError(f"{FIELD_ENCRYPTION_KEY_ENV} must be urlsafe base64") from exc
    if len(raw) not in {16, 24, 32}:
        raise FieldDecryptionError(f"{FIELD_ENCRYPTION_KEY_ENV} must decode to 16, 24, or 32 bytes")
    return raw


def encrypt_field(value: str | None) -> str | None:
    if value is None or value == "":
        return value
    if is_encrypted_value(value) or not field_encryption_enabled():
        return value
    key = _field_key()
    if key is None:
        return value
    nonce = os.urandom(12)
    ciphertext = AESGCM(key).encrypt(nonce, value.encode("utf-8"), FIELD_ENCRYPTION_PREFIX.encode("ascii"))
    return FIELD_ENCRYPTION_PREFIX + base64.urlsafe_b64encode(nonce + ciphertext).decode("ascii")


def decrypt_field(value: str | None) -> str | None:
    if value is None or not is_encrypted_value(value):
        return value
    key = _field_key()
    if key is None:
        return "[encrypted-field]"
    payload = value[len(FIELD_ENCRYPTION_PREFIX):]
    try:
        raw = base64.urlsafe_b64decode(payload.encode("ascii"))
        nonce, ciphertext = raw[:12], raw[12:]
        plaintext = AESGCM(key).decrypt(nonce, ciphertext, FIELD_ENCRYPTION_PREFIX.encode("ascii"))
    except (ValueError, InvalidTag) as exc:
        raise FieldDecryptionError("Encrypted field cannot be decrypted") from exc
    return plaintext.decode("utf-8")
