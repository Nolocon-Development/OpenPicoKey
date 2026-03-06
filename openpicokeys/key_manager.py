from __future__ import annotations

import json
import struct
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from .crypto_backup import BackupCryptoError, decrypt_backup, encrypt_backup


class KeyManagerError(RuntimeError):
    """Raised when a backup manager operation fails."""


@dataclass(frozen=True)
class DeviceCapabilities:
    """Capabilities reported by the connected Pico key device."""

    export_supported: bool
    restore_supported: bool
    device_id: str = ""
    firmware_version: str = ""
    message: str = ""


class DeviceTransport:
    """Transport contract for backup/restore device communication."""

    def probe(self) -> DeviceCapabilities:
        raise NotImplementedError

    def export_data(self) -> bytes:
        raise NotImplementedError

    def import_data(self, payload: bytes) -> None:
        raise NotImplementedError


class PicoKeyStubTransport(DeviceTransport):
    """Current placeholder transport until firmware export/import API exists."""

    def probe(self) -> DeviceCapabilities:
        return DeviceCapabilities(
            export_supported=False,
            restore_supported=False,
            device_id="",
            firmware_version="",
            message=(
                "Connected transport does not expose backup/restore commands yet. "
                "Firmware export/import support is required."
            ),
        )

    def export_data(self) -> bytes:
        raise KeyManagerError(
            "Backup is unavailable: firmware export command is not implemented."
        )

    def import_data(self, payload: bytes) -> None:
        _ = payload
        raise KeyManagerError(
            "Restore is unavailable: firmware import command is not implemented."
        )


class KeyManagerService:
    """High-level service for encrypted backup and restore workflows."""

    def __init__(self, transport: DeviceTransport | None = None, log_callback=None) -> None:
        self._transport = transport or default_transport()
        self._log_cb = log_callback or (lambda _: None)

    def _log(self, message: str) -> None:
        self._log_cb(message)

    def probe_device(self) -> DeviceCapabilities:
        caps = self._transport.probe()
        if caps.message:
            self._log(caps.message)
        return caps

    def backup_to_file(self, target: Path, password: str) -> Path:
        caps = self.probe_device()
        if not caps.export_supported:
            raise KeyManagerError(caps.message or "Device does not support backup export.")

        payload = self._transport.export_data()
        metadata = {
            "created_at_utc": datetime.now(timezone.utc).isoformat(),
            "scope": "firmware_capability_export",
            "device_id": caps.device_id,
            "firmware_version": caps.firmware_version,
            "payload_format": "application/octet-stream",
        }
        encrypted = encrypt_backup(payload=payload, password=password, metadata=metadata)

        target = target.expanduser().resolve()
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(encrypted)
        self._log(f"Encrypted backup saved: {target}")
        return target

    def restore_from_file(self, source: Path, password: str) -> None:
        source = source.expanduser().resolve()
        if not source.is_file():
            raise KeyManagerError(f"Backup file not found: {source}")

        caps = self.probe_device()
        if not caps.restore_supported:
            raise KeyManagerError(caps.message or "Device does not support restore import.")

        try:
            decrypted = decrypt_backup(source.read_bytes(), password=password)
        except BackupCryptoError as exc:
            raise KeyManagerError(str(exc)) from exc

        if not decrypted.payload:
            raise KeyManagerError("Backup payload is empty.")

        # Optional safety: when both IDs exist, require same-device restore.
        backup_device_id = str(decrypted.metadata.get("device_id", "")).strip()
        if backup_device_id and caps.device_id and backup_device_id != caps.device_id:
            raise KeyManagerError(
                "Backup device ID does not match the connected device. "
                "Cross-device restore is blocked for safety."
            )

        self._transport.import_data(decrypted.payload)
        self._log(f"Restore completed from: {source}")

    @staticmethod
    def summarize_metadata_from_file(source: Path, password: str) -> dict[str, str]:
        """Decrypt and return safe-to-display metadata for preview purposes."""
        source = source.expanduser().resolve()
        if not source.is_file():
            raise KeyManagerError(f"Backup file not found: {source}")
        try:
            dec = decrypt_backup(source.read_bytes(), password=password)
        except BackupCryptoError as exc:
            raise KeyManagerError(str(exc)) from exc
        safe = {
            "created_at_utc": str(dec.metadata.get("created_at_utc", "unknown")),
            "device_id": str(dec.metadata.get("device_id", "unknown")) or "unknown",
            "firmware_version": str(dec.metadata.get("firmware_version", "unknown")) or "unknown",
            "scope": str(dec.metadata.get("scope", "unknown")) or "unknown",
            "payload_bytes": str(len(dec.payload)),
        }
        return safe

    @staticmethod
    def metadata_json(source: Path, password: str) -> str:
        return json.dumps(KeyManagerService.summarize_metadata_from_file(source, password), indent=2)


class PicoKeyFidoTransport(DeviceTransport):
    """CTAP vendor transport for Pico FIDO backup/restore commands."""

    _CTAPHID_VENDOR_CBOR = 0x41
    _CTAP_VENDOR_BACKUP = 0x01
    _SUB_LIST_FILES = 0x10
    _SUB_EXPORT_FILE = 0x11
    _SUB_IMPORT_FILE = 0x12
    _SUB_CLEAR_FILES = 0x13
    _PAYLOAD_MAGIC = b"PKDB1"

    def __init__(self) -> None:
        try:
            from fido2 import cbor as fido_cbor  # type: ignore
            from fido2.ctap import CtapError  # type: ignore
            from fido2.ctap2 import Ctap2  # type: ignore
            from fido2.hid import CtapHidDevice  # type: ignore
        except Exception as exc:
            raise KeyManagerError(
                "Missing dependency: python-fido2 is required for Backup Manager transport."
            ) from exc

        self._fido_cbor = fido_cbor
        self._CtapError = CtapError
        self._Ctap2 = Ctap2
        self._CtapHidDevice = CtapHidDevice

    def _open_ctap(self):
        devices = list(self._CtapHidDevice.list_devices())
        if not devices:
            raise KeyManagerError("No FIDO device detected. Connect your Pico key and try again.")
        return self._Ctap2(devices[0]), devices[0]

    def _vendor_call(self, vendor_cmd: int, vendor_param: bytes | None = None) -> dict:
        _ctap, device = self._open_ctap()
        data: dict[int, object] = {1: vendor_cmd}
        if vendor_param is not None:
            data[2] = {1: vendor_param}
        req = struct.pack(">B", self._CTAP_VENDOR_BACKUP) + self._fido_cbor.encode(data)
        try:
            raw = device.call(self._CTAPHID_VENDOR_CBOR, req)
        except self._CtapError as exc:
            raise KeyManagerError(
                f"Firmware vendor command failed (0x{vendor_cmd:02X}): {exc}"
            ) from exc
        except Exception as exc:
            raise KeyManagerError(f"Firmware vendor command failed (0x{vendor_cmd:02X}): {exc}") from exc

        if not raw:
            raise KeyManagerError("Firmware vendor command returned an empty response.")
        status = raw[0]
        if status != 0x00:
            raise KeyManagerError(
                f"Firmware vendor command failed (0x{vendor_cmd:02X}): CTAP status 0x{status:02X}"
            )
        payload = raw[1:]
        if not payload:
            return {}
        try:
            response = self._fido_cbor.decode(payload)
        except Exception as exc:
            raise KeyManagerError(
                f"Firmware vendor command failed (0x{vendor_cmd:02X}): invalid CBOR response"
            ) from exc
        if not isinstance(response, dict):
            raise KeyManagerError("Unexpected firmware response format.")
        return response

    @staticmethod
    def _device_id(device: object) -> str:
        descriptor = getattr(device, "descriptor", None)
        if descriptor is None:
            return ""
        for attr in ("serial_number", "path", "product_string"):
            val = getattr(descriptor, attr, None)
            if isinstance(val, str) and val.strip():
                return val.strip()
        return ""

    def probe(self) -> DeviceCapabilities:
        try:
            ctap, device = self._open_ctap()
            _ = ctap  # used for open test
            response = self._vendor_call(self._SUB_LIST_FILES)
            files = response.get(1, [])
            count = len(files) if isinstance(files, list) else 0
            return DeviceCapabilities(
                export_supported=True,
                restore_supported=True,
                device_id=self._device_id(device),
                firmware_version="",
                message=f"Backup transport ready ({count} file entries detected).",
            )
        except KeyManagerError as exc:
            return DeviceCapabilities(
                export_supported=False,
                restore_supported=False,
                device_id="",
                firmware_version="",
                message=str(exc),
            )

    def export_data(self) -> bytes:
        listing = self._vendor_call(self._SUB_LIST_FILES)
        entries = listing.get(1, [])
        if not isinstance(entries, list):
            raise KeyManagerError("Invalid file listing payload from firmware.")

        out = bytearray()
        out.extend(self._PAYLOAD_MAGIC)
        out.extend(struct.pack(">H", len(entries)))

        for entry in entries:
            if not isinstance(entry, dict):
                raise KeyManagerError("Invalid file entry in firmware listing.")
            try:
                fid = int(entry[1])
            except Exception as exc:
                raise KeyManagerError("Missing or invalid file ID in firmware listing.") from exc

            res = self._vendor_call(self._SUB_EXPORT_FILE, struct.pack(">H", fid))
            data = res.get(2)
            if not isinstance(data, (bytes, bytearray)):
                raise KeyManagerError(f"Invalid payload for file 0x{fid:04X}.")
            blob = bytes(data)
            out.extend(struct.pack(">HI", fid, len(blob)))
            out.extend(blob)

        return bytes(out)

    def import_data(self, payload: bytes) -> None:
        if len(payload) < 7 or not payload.startswith(self._PAYLOAD_MAGIC):
            raise KeyManagerError("Invalid backup payload magic.")

        offset = len(self._PAYLOAD_MAGIC)
        try:
            total = struct.unpack_from(">H", payload, offset)[0]
        except Exception as exc:
            raise KeyManagerError("Backup payload header is truncated.") from exc
        offset += 2

        parsed: list[tuple[int, bytes]] = []
        for _ in range(total):
            if offset + 6 > len(payload):
                raise KeyManagerError("Backup payload is truncated.")
            fid, length = struct.unpack_from(">HI", payload, offset)
            offset += 6
            if offset + length > len(payload):
                raise KeyManagerError("Backup payload length mismatch.")
            parsed.append((fid, payload[offset : offset + length]))
            offset += length

        # Start from a clean state before replaying backup records.
        self._vendor_call(self._SUB_CLEAR_FILES)

        for fid, blob in parsed:
            param = struct.pack(">H", fid) + blob
            self._vendor_call(self._SUB_IMPORT_FILE, param)


def default_transport() -> DeviceTransport:
    try:
        return PicoKeyFidoTransport()
    except KeyManagerError:
        return PicoKeyStubTransport()
