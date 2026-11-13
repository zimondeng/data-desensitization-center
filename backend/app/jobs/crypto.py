from __future__ import annotations

import base64
import binascii
import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

_NONCE_LEN = 12
_GCM_TAG_LEN = 16


def _validate_key(key_32_bytes: bytes) -> None:
    if not isinstance(key_32_bytes, (bytes, bytearray)) or len(key_32_bytes) != 32:
        raise ValueError("AES-256-GCM master key must be exactly 32 bytes")


def encrypt_secret(plaintext: str, key_32_bytes: bytes) -> str:
    """Encrypt secret with AES-256-GCM using a fresh 12-byte random nonce."""
    _validate_key(key_32_bytes)
    if not isinstance(plaintext, str) or not plaintext:
        raise ValueError("Secret plaintext must be a non-empty string")
    nonce = os.urandom(_NONCE_LEN)
    ciphertext = AESGCM(bytes(key_32_bytes)).encrypt(
        nonce, plaintext.encode("utf-8"), None
    )
    return base64.urlsafe_b64encode(nonce + ciphertext).decode("ascii")


def decrypt_secret(cipher_b64: str, key_32_bytes: bytes) -> str:
    """Decrypt AES-256-GCM base64url token without leaking cipher or plaintext on error."""
    _validate_key(key_32_bytes)
    if not isinstance(cipher_b64, str) or not cipher_b64.strip():
        raise ValueError("Invalid encrypted secret token")
    try:
        raw = base64.urlsafe_b64decode(cipher_b64.strip().encode("ascii"))
    except (binascii.Error, UnicodeEncodeError):
        raise ValueError("Malformed encrypted secret encoding") from None

    if len(raw) < _NONCE_LEN + _GCM_TAG_LEN:
        raise ValueError("Truncated encrypted secret payload")

    nonce, ct = raw[:_NONCE_LEN], raw[_NONCE_LEN:]
    try:
        plain_bytes = AESGCM(bytes(key_32_bytes)).decrypt(nonce, ct, None)
        return plain_bytes.decode("utf-8")
    except (InvalidTag, UnicodeDecodeError):
        raise ValueError("Datasource secret authentication failed") from None
