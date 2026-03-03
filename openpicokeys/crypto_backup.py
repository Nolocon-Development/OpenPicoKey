from __future__ import annotations

import base64
import json
import os
from dataclasses import dataclass
from typing import Any

from argon2.low_level import Type, hash_secret_raw
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class BackupCryptoError(RuntimeError):
    """Raised when backup encryption/decryption fails."""


@dataclass(frozen=True)
class EncryptedBackup:
    """Decrypted backup payload with associated metadata."""

    metadata: dict[str, Any]
    payload: bytes


_FORMAT = "openpicokeys-key-manager-v1"


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _unb64(value: str, label: str) -> bytes:
    try:
        return base64.b64decode(value.encode("ascii"), validate=True)
    except Exception as exc:
        raise BackupCryptoError(f"Invalid base64 in backup field '{label}'.") from exc


def _derive_key(password: str, salt: bytes, time_cost: int, memory_kib: int, parallelism: int) -> bytes:
    try:
        return hash_secret_raw(
            secret=password.encode("utf-8"),
            salt=salt,
            time_cost=time_cost,
            memory_cost=memory_kib,
            parallelism=parallelism,
            hash_len=32,
            type=Type.ID,
        )
    except Exception as exc:
        raise BackupCryptoError("Failed to derive encryption key from password.") from exc


def encrypt_backup(payload: bytes, password: str, metadata: dict[str, Any]) -> bytes:
    """Return encrypted backup bytes for *payload* and JSON-compatible *metadata*."""
    if not password:
        raise BackupCryptoError("Backup password cannot be empty.")

    salt = os.urandom(16)
    nonce = os.urandom(12)
    kdf = {
        "name": "argon2id",
        "time_cost": 3,
        "memory_kib": 65536,
        "parallelism": 1,
        "salt_b64": _b64(salt),
    }

    header = {
        "format": _FORMAT,
        "kdf": kdf,
        "meta": metadata,
    }
    aad = json.dumps(header, sort_keys=True, separators=(",", ":")).encode("utf-8")

    key = _derive_key(
        password=password,
        salt=salt,
        time_cost=kdf["time_cost"],
        memory_kib=kdf["memory_kib"],
        parallelism=kdf["parallelism"],
    )
    ciphertext = AESGCM(key).encrypt(nonce, payload, aad)

    envelope = {
        **header,
        "enc": {
            "name": "aes-256-gcm",
            "nonce_b64": _b64(nonce),
            "ciphertext_b64": _b64(ciphertext),
        },
    }
    return json.dumps(envelope, indent=2, ensure_ascii=False).encode("utf-8")


def decrypt_backup(encrypted: bytes, password: str) -> EncryptedBackup:
    """Decrypt an encrypted backup blob and return metadata + payload."""
    if not password:
        raise BackupCryptoError("Backup password cannot be empty.")

    try:
        envelope = json.loads(encrypted.decode("utf-8"))
    except Exception as exc:
        raise BackupCryptoError("Backup file is not valid JSON.") from exc

    if not isinstance(envelope, dict):
        raise BackupCryptoError("Backup file format is invalid.")

    fmt = envelope.get("format")
    if fmt != _FORMAT:
        raise BackupCryptoError(f"Unsupported backup format: {fmt!r}")

    kdf = envelope.get("kdf")
    enc = envelope.get("enc")
    meta = envelope.get("meta", {})
    if not isinstance(kdf, dict) or not isinstance(enc, dict):
        raise BackupCryptoError("Backup file is missing encryption metadata.")

    if kdf.get("name") != "argon2id":
        raise BackupCryptoError("Unsupported KDF in backup file.")
    if enc.get("name") != "aes-256-gcm":
        raise BackupCryptoError("Unsupported encryption algorithm in backup file.")

    salt = _unb64(str(kdf.get("salt_b64", "")), "kdf.salt_b64")
    nonce = _unb64(str(enc.get("nonce_b64", "")), "enc.nonce_b64")
    ciphertext = _unb64(str(enc.get("ciphertext_b64", "")), "enc.ciphertext_b64")

    try:
        time_cost = int(kdf["time_cost"])
        memory_kib = int(kdf["memory_kib"])
        parallelism = int(kdf["parallelism"])
    except Exception as exc:
        raise BackupCryptoError("Invalid KDF parameters in backup file.") from exc

    header = {
        "format": fmt,
        "kdf": kdf,
        "meta": meta,
    }
    aad = json.dumps(header, sort_keys=True, separators=(",", ":")).encode("utf-8")
    key = _derive_key(
        password=password,
        salt=salt,
        time_cost=time_cost,
        memory_kib=memory_kib,
        parallelism=parallelism,
    )

    try:
        payload = AESGCM(key).decrypt(nonce, ciphertext, aad)
    except Exception as exc:
        raise BackupCryptoError(
            "Failed to decrypt backup. Password is incorrect or file is corrupted."
        ) from exc

    if not isinstance(meta, dict):
        raise BackupCryptoError("Backup metadata is invalid.")
    return EncryptedBackup(metadata=meta, payload=payload)
