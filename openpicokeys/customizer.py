"""Binary UF2 firmware patcher for USB descriptor customization.

The customizer rewrites constant data (strings, VID/PID) in an existing UF2
firmware image so the device shows different USB product information after
flashing.  Because only read-only data changes and the code is byte-identical,
all passkey / credential data stored on the device is preserved.
"""

from __future__ import annotations

import re
import struct
from dataclasses import dataclass
from pathlib import Path


class CustomizerError(RuntimeError):
    """Raised when firmware customization fails."""


@dataclass
class UF2Info:
    """Metadata parsed from a UF2 firmware file."""

    base_address: int
    family_id: int
    total_size: int
    board: str


@dataclass
class FirmwareCustomization:
    """USB descriptor values detected in (or desired for) a firmware image."""

    key_name: str = ""
    manufacturer: str = ""
    website: str = ""
    usb_vid: int = 0
    usb_pid: int = 0


class FirmwareCustomizer:
    """Patches USB descriptor customization in an existing UF2 binary.

    Limitations
    -----------
    * New string values must not exceed the **byte-length** of the current
      value in the binary.  There is no room to grow an in-place constant.
    * When manufacturer and product name are identical in the firmware, the
      compiler may merge them into one copy; they can then only be changed
      **together** to the same new value.
    * LED-disable cannot be toggled by binary patching (requires rebuild).
    """

    _UF2_MAGIC0 = 0x0A324655
    _UF2_MAGIC1 = 0x9E5D5157
    _UF2_MAGIC_END = 0x0AB16F30
    _UF2_FLAG_FAM = 0x00002000
    _PAYLOAD = 256
    _BLOCK = 512

    _FAMILY_BOARDS: dict[int, str] = {
        0xE48BFF56: "pico",  # RP2040
        0xE48BFF59: "pico2",  # RP2350
    }

    _KNOWN_PRODUCT_STRINGS = (
        "OpenPicoKeys",
        "Pico Key",
        "Pico FIDO",
        "PicoKey",
        "FIDO2 Key",
    )

    _KNOWN_URL_STRINGS = (
        "www.openpicokeys.local",
        "picokeys.local",
    )

    def __init__(self, log_callback=None) -> None:
        self._log_cb = log_callback or (lambda _: None)

    def _log(self, msg: str) -> None:
        self._log_cb(msg)

    # ------------------------------------------------------------------ #
    #  UF2 I/O                                                            #
    # ------------------------------------------------------------------ #

    def read_uf2(self, path: Path) -> tuple[bytearray, UF2Info]:
        """Parse *path* into ``(flat_binary, info)``."""
        raw = path.read_bytes()
        if len(raw) % self._BLOCK:
            raise CustomizerError(
                "Invalid UF2: file size is not a multiple of 512 bytes."
            )
        n = len(raw) // self._BLOCK
        if n == 0:
            raise CustomizerError("UF2 file contains no data blocks.")

        entries: list[tuple[int, bytes]] = []
        fam = 0
        for i in range(n):
            o = i * self._BLOCK
            b = raw[o : o + self._BLOCK]
            m0, m1, _fl, addr, _sz, _bno, _tot, fi = struct.unpack_from(
                "<IIIIIIII", b
            )
            me = struct.unpack_from("<I", b, 508)[0]
            if (
                m0 != self._UF2_MAGIC0
                or m1 != self._UF2_MAGIC1
                or me != self._UF2_MAGIC_END
            ):
                raise CustomizerError(f"Invalid UF2 magic in block {i}.")
            if i == 0:
                fam = fi
            entries.append((addr, b[32 : 32 + self._PAYLOAD]))

        entries.sort(key=lambda e: e[0])
        base = entries[0][0]
        end = entries[-1][0] + self._PAYLOAD
        flat = bytearray(end - base)
        for addr, payload in entries:
            flat[addr - base : addr - base + self._PAYLOAD] = payload

        board = self._FAMILY_BOARDS.get(fam, "unknown")
        info = UF2Info(base, fam, len(flat), board)
        self._log(f"Read UF2: {n} blocks, {len(flat):,} bytes, board={board}")
        return flat, info

    def write_uf2(self, flat: bytearray, info: UF2Info, path: Path) -> None:
        """Write *flat* binary back to UF2 at *path*."""
        ps = self._PAYLOAD
        total = (len(flat) + ps - 1) // ps
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("wb") as fh:
            for bno in range(total):
                off = bno * ps
                chunk = flat[off : off + ps]
                if len(chunk) < ps:
                    chunk += bytes(ps - len(chunk))
                blk = bytearray(self._BLOCK)
                struct.pack_into(
                    "<IIIIIIII",
                    blk,
                    0,
                    self._UF2_MAGIC0,
                    self._UF2_MAGIC1,
                    self._UF2_FLAG_FAM,
                    info.base_address + off,
                    ps,
                    bno,
                    total,
                    info.family_id,
                )
                blk[32 : 32 + ps] = chunk
                struct.pack_into("<I", blk, 508, self._UF2_MAGIC_END)
                fh.write(blk)
        self._log(f"Wrote UF2: {total} blocks -> {path}")

    # ------------------------------------------------------------------ #
    #  Binary helpers                                                     #
    # ------------------------------------------------------------------ #

    @staticmethod
    def _find_all(data: bytearray, pattern: bytes) -> list[int]:
        """Return every offset where *pattern* occurs in *data*."""
        out: list[int] = []
        s = 0
        while True:
            p = data.find(pattern, s)
            if p < 0:
                break
            out.append(p)
            s = p + 1
        return out

    def _find_null_terminated(self, data: bytearray, text: str) -> list[int]:
        """Find all offsets of the null-terminated ASCII *text* in *data*."""
        return self._find_all(data, text.encode("ascii") + b"\x00")

    def _find_device_descriptor(self, data: bytearray) -> int | None:
        """Locate the 18-byte USB device descriptor in a firmware binary."""
        for pos in self._find_all(data, b"\x12\x01"):
            if pos + 18 > len(data):
                continue
            bcd = struct.unpack_from("<H", data, pos + 2)[0]
            if bcd not in (0x0110, 0x0200, 0x0201, 0x0210, 0x0300, 0x0310):
                continue
            if data[pos + 7] not in (8, 16, 32, 64):
                continue
            if not 1 <= data[pos + 17] <= 4:
                continue
            if data[pos + 14] > 10 or data[pos + 15] > 10:
                continue
            self._log(f"USB device descriptor at offset 0x{pos:X}")
            return pos
        return None

    # ------------------------------------------------------------------ #
    #  Scan                                                               #
    # ------------------------------------------------------------------ #

    def scan_customization(self, data: bytearray) -> FirmwareCustomization:
        """Best-effort auto-detect of current USB descriptor values.

        VID/PID detection is reliable.  String detection tries a list of
        known defaults and falls back to heuristic URL scanning.
        """
        c = FirmwareCustomization()

        # --- VID / PID ---
        dd = self._find_device_descriptor(data)
        if dd is not None:
            c.usb_vid = struct.unpack_from("<H", data, dd + 8)[0]
            c.usb_pid = struct.unpack_from("<H", data, dd + 10)[0]
            self._log(f"Detected VID=0x{c.usb_vid:04X}  PID=0x{c.usb_pid:04X}")

        # --- product / manufacturer strings ---
        for s in self._KNOWN_PRODUCT_STRINGS:
            if self._find_null_terminated(data, s):
                c.manufacturer = s
                c.key_name = s
                self._log(f"Detected product / manufacturer string: '{s}'")
                break

        # --- WebUSB URL ---
        for s in self._KNOWN_URL_STRINGS:
            if self._find_null_terminated(data, s):
                c.website = s
                self._log(f"Detected URL: '{s}'")
                break

        if not c.website:
            # Heuristic: search for domain-like ASCII strings
            pat = re.compile(
                rb"((?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+"
                rb"[a-zA-Z]{2,10}(?:/[\x21-\x7e]*)?)\x00",
            )
            for m in pat.finditer(bytes(data)):
                url = m.group(1).decode("ascii", errors="replace")
                if 4 <= len(url) <= 120:
                    c.website = url
                    self._log(f"Heuristic URL: '{url}'")
                    break

        if not c.key_name and not c.manufacturer:
            self._log(
                "Could not auto-detect product / manufacturer strings.  "
                "Enter current values manually or load a build profile."
            )

        return c

    # ------------------------------------------------------------------ #
    #  Patch                                                              #
    # ------------------------------------------------------------------ #

    def _patch_string(
        self, data: bytearray, old: str, new: str, label: str
    ) -> int:
        """Replace null-terminated *old* with *new* (zero-padded).

        Returns the number of replacements made.
        """
        if old == new:
            return 0
        old_b = old.encode("ascii") + b"\x00"
        new_b = new.encode("ascii")
        padded = new_b + b"\x00" * (len(old_b) - len(new_b))
        count, s = 0, 0
        while True:
            p = data.find(old_b, s)
            if p < 0:
                break
            data[p : p + len(padded)] = padded
            count += 1
            s = p + len(padded)
        if count:
            self._log(f"Patched {label}: '{old}' -> '{new}' ({count}x)")
        return count

    def _patch_vid_pid(
        self,
        data: bytearray,
        old_vid: int,
        old_pid: int,
        new_vid: int,
        new_pid: int,
    ) -> None:
        """Replace VID/PID in the USB device descriptor."""
        dd = self._find_device_descriptor(data)
        if dd is None:
            raise CustomizerError("USB device descriptor not found in binary.")
        cv = struct.unpack_from("<H", data, dd + 8)[0]
        cp = struct.unpack_from("<H", data, dd + 10)[0]
        if cv != old_vid or cp != old_pid:
            raise CustomizerError(
                f"VID/PID mismatch: expected "
                f"0x{old_vid:04X}:0x{old_pid:04X}, "
                f"found 0x{cv:04X}:0x{cp:04X}."
            )
        struct.pack_into("<H", data, dd + 8, new_vid)
        struct.pack_into("<H", data, dd + 10, new_pid)
        self._log(
            f"Patched VID/PID: "
            f"0x{old_vid:04X}:0x{old_pid:04X} -> "
            f"0x{new_vid:04X}:0x{new_pid:04X}"
        )

    @staticmethod
    def parse_hex_word(value: str, label: str) -> int:
        """Parse a hex string like ``0x2E8A`` into an integer."""
        raw = value.strip().lower().removeprefix("0x")
        if not re.fullmatch(r"[0-9a-f]{1,4}", raw):
            raise CustomizerError(
                f"{label} must be a 1\u20134 digit hex value (e.g. 0x2E8A)."
            )
        return int(raw, 16)

    @staticmethod
    def _check_len(label: str, old: str, new: str) -> None:
        if not new.strip():
            raise CustomizerError(f"{label} cannot be empty.")
        if len(new) > len(old):
            raise CustomizerError(
                f"{label}: new value '{new}' ({len(new)} chars) exceeds "
                f"the firmware allocation ({len(old)} chars).  "
                f"Use a shorter value or rebuild the firmware."
            )

    def apply_patches(
        self,
        data: bytearray,
        current: FirmwareCustomization,
        new: FirmwareCustomization,
    ) -> tuple[bytearray, list[str]]:
        """Return ``(patched_copy, list_of_change_descriptions)``."""
        out = bytearray(data)
        changes: list[str] = []

        # --- strings ---
        same_src = (
            current.manufacturer
            and current.key_name
            and current.manufacturer == current.key_name
        )

        if same_src:
            # Compiler may have merged identical literals – treat as one slot.
            if new.manufacturer != new.key_name:
                raise CustomizerError(
                    "This firmware stores key name and manufacturer as the same "
                    "string.  They can only be changed to the same new value.  "
                    "To set different values, rebuild the firmware instead."
                )
            if new.manufacturer and new.manufacturer != current.manufacturer:
                self._check_len(
                    "Key name / manufacturer",
                    current.manufacturer,
                    new.manufacturer,
                )
                n = self._patch_string(
                    out,
                    current.manufacturer,
                    new.manufacturer,
                    "key name / manufacturer",
                )
                if not n:
                    raise CustomizerError(
                        f"'{current.manufacturer}' not found in the firmware binary."
                    )
                changes.append(
                    f"Key name / manufacturer: "
                    f"'{current.manufacturer}' \u2192 '{new.manufacturer}'"
                )
        else:
            if (
                current.key_name
                and new.key_name
                and new.key_name != current.key_name
            ):
                self._check_len("Key name", current.key_name, new.key_name)
                n = self._patch_string(
                    out, current.key_name, new.key_name, "key name"
                )
                if not n:
                    raise CustomizerError(
                        f"Key name '{current.key_name}' not found in binary."
                    )
                changes.append(
                    f"Key name: '{current.key_name}' \u2192 '{new.key_name}'"
                )

            if (
                current.manufacturer
                and new.manufacturer
                and new.manufacturer != current.manufacturer
            ):
                self._check_len(
                    "Manufacturer", current.manufacturer, new.manufacturer
                )
                n = self._patch_string(
                    out,
                    current.manufacturer,
                    new.manufacturer,
                    "manufacturer",
                )
                if not n:
                    raise CustomizerError(
                        f"Manufacturer '{current.manufacturer}' not found in binary."
                    )
                changes.append(
                    f"Manufacturer: '{current.manufacturer}' \u2192 "
                    f"'{new.manufacturer}'"
                )

        if current.website and new.website and new.website != current.website:
            self._check_len("Website", current.website, new.website)
            n = self._patch_string(
                out, current.website, new.website, "website"
            )
            if not n:
                raise CustomizerError(
                    f"Website '{current.website}' not found in binary."
                )
            changes.append(
                f"Website: '{current.website}' \u2192 '{new.website}'"
            )

        # --- VID / PID ---
        if new.usb_vid != current.usb_vid or new.usb_pid != current.usb_pid:
            self._patch_vid_pid(
                out,
                current.usb_vid,
                current.usb_pid,
                new.usb_vid,
                new.usb_pid,
            )
            changes.append(
                f"VID/PID: "
                f"0x{current.usb_vid:04X}:0x{current.usb_pid:04X} \u2192 "
                f"0x{new.usb_vid:04X}:0x{new.usb_pid:04X}"
            )

        return out, changes

    # ------------------------------------------------------------------ #
    #  Public high-level API                                              #
    # ------------------------------------------------------------------ #

    def optimize(
        self,
        input_path: Path,
        output_path: Path,
        current: FirmwareCustomization,
        new: FirmwareCustomization,
    ) -> Path:
        """Read \u2192 patch \u2192 write.  Returns *output_path* on success."""
        self._log(f"Reading: {input_path}")
        flat, info = self.read_uf2(input_path)
        patched, changes = self.apply_patches(flat, current, new)
        if not changes:
            self._log("No changes to apply \u2014 writing identical copy.")
        self.write_uf2(patched, info, output_path)
        for ch in changes:
            self._log(f"  \u2713 {ch}")
        self._log(f"Optimized firmware saved: {output_path}")
        return output_path
