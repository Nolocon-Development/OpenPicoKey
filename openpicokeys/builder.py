from __future__ import annotations

import os
import re
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse

from .models import BuildProfile


UPSTREAM_PICO_FIDO_REPO = "https://github.com/polhenarejos/pico-fido.git"
DESCRIPTORS_RELATIVE_PATH = Path("pico-keys-sdk/src/usb/usb_descriptors.c")
LED_RELATIVE_PATH = Path("pico-keys-sdk/src/led/led.c")


class BuildError(RuntimeError):
    pass


@dataclass
class BuildResult:
    output_uf2: Path
    build_dir: Path


class FirmwareBuilder:
    def __init__(self, log_callback=None) -> None:
        self._log_callback = log_callback or (lambda _: None)

    def _log(self, message: str) -> None:
        self._log_callback(message)

    def _run(self, cmd: list[str], cwd: Path, env: dict | None = None) -> None:
        self._log(f"$ {' '.join(cmd)}")
        proc = subprocess.Popen(
            cmd,
            cwd=str(cwd),
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        assert proc.stdout is not None
        for line in proc.stdout:
            self._log(line.rstrip())
        rc = proc.wait()
        if rc != 0:
            raise BuildError(f"Command failed with exit code {rc}: {' '.join(cmd)}")

    @staticmethod
    def dependency_install_commands() -> dict[str, list[list[str]]]:
        return {
            "git": [
                [
                    "winget",
                    "install",
                    "--id",
                    "Git.Git",
                    "-e",
                    "--source",
                    "winget",
                    "--accept-package-agreements",
                    "--accept-source-agreements",
                ]
            ],
            "cmake": [
                [
                    "winget",
                    "install",
                    "--id",
                    "Kitware.CMake",
                    "-e",
                    "--source",
                    "winget",
                    "--accept-package-agreements",
                    "--accept-source-agreements",
                ]
            ],
            "arm-none-eabi-gcc": [
                [
                    "winget",
                    "install",
                    "--id",
                    "Arm.GnuArmEmbeddedToolchain",
                    "-e",
                    "--source",
                    "winget",
                    "--accept-package-agreements",
                    "--accept-source-agreements",
                ]
            ],
        }

    @staticmethod
    def dependency_display_names() -> dict[str, str]:
        return {
            "git": "Git",
            "cmake": "CMake",
            "arm-none-eabi-gcc": "GNU Arm Embedded Toolchain",
        }

    @classmethod
    def required_dependencies(cls, for_build: bool) -> list[str]:
        if for_build:
            return ["git", "cmake", "arm-none-eabi-gcc"]
        return ["git"]

    @classmethod
    def missing_dependencies(cls, for_build: bool) -> list[str]:
        missing: list[str] = []
        for tool in cls.required_dependencies(for_build=for_build):
            if shutil.which(tool) is None:
                missing.append(tool)
        return missing

    def install_dependency(self, dependency: str) -> None:
        commands = self.dependency_install_commands().get(dependency)
        if not commands:
            raise BuildError(f"No installer is configured for dependency: {dependency}")
        if shutil.which("winget") is None:
            raise BuildError(
                "Auto-install requires `winget`, but it was not found. Install the dependency manually."
            )

        self._log(f"Installing dependency: {dependency}")
        for cmd in commands:
            self._run(cmd, cwd=Path.cwd())
        self._log(f"Dependency installed: {dependency}")

    @staticmethod
    def _normalize_hex_word(value: str, label: str) -> str:
        raw = value.strip().lower()
        if raw.startswith("0x"):
            raw = raw[2:]
        if not re.fullmatch(r"[0-9a-f]{1,4}", raw):
            raise BuildError(f"{label} must be a 1-4 digit hexadecimal value.")
        return f"0x{raw.upper().zfill(4)}"

    @staticmethod
    def _escape_c_string(value: str) -> str:
        return value.replace("\\", "\\\\").replace('"', '\\"')

    @staticmethod
    def _sanitize_website(value: str) -> str:
        candidate = value.strip()
        if not candidate:
            raise BuildError("Website cannot be empty.")

        parsed = urlparse(candidate if "://" in candidate else f"https://{candidate}")
        result = (parsed.netloc + parsed.path).strip()
        if not result:
            result = candidate
        result = result.lstrip("/")
        if len(result) > 120:
            raise BuildError("Website value is too long (max 120 chars).")
        return result

    def _patch_descriptors(self, descriptor_path: Path, profile: BuildProfile) -> str:
        source = descriptor_path.read_text(encoding="utf-8")
        patched = source

        website = self._escape_c_string(self._sanitize_website(profile.website))
        manufacturer = self._escape_c_string(profile.manufacturer.strip())
        key_name = self._escape_c_string(profile.key_name.strip())

        if not manufacturer:
            raise BuildError("Manufacturer cannot be empty.")
        if not key_name:
            raise BuildError("Key name cannot be empty.")
        if len(manufacturer) > 31:
            raise BuildError("Manufacturer must be 31 characters or fewer.")
        if len(key_name) > 24:
            raise BuildError("Key name must be 24 characters or fewer.")

        patched, url_count = re.subn(
            r'(#define\s+URL\s+)"[^"]*"',
            lambda m: f'{m.group(1)}"{website}"',
            patched,
            count=1,
        )
        patched, manufacturer_count = re.subn(
            r'"[^"]*"\s*,\s*//\s*1:\s*Manufacturer',
            lambda _: f'"{manufacturer}",                     // 1: Manufacturer',
            patched,
            count=1,
        )
        patched, product_count = re.subn(
            r'"[^"]*"\s*,\s*//\s*2:\s*Product',
            lambda _: f'"{key_name}",                       // 2: Product',
            patched,
            count=1,
        )

        if url_count != 1 or manufacturer_count != 1 or product_count != 1:
            raise BuildError(
                "Failed to patch pico-keys-sdk descriptors. The upstream file format may have changed."
            )

        descriptor_path.write_text(patched, encoding="utf-8")
        return source

    def _patch_led(self, led_path: Path, disable_led: bool) -> str:
        source = led_path.read_text(encoding="utf-8")
        if not disable_led:
            return source

        injection = (
            "#ifdef OPENPICOKEYS_DISABLE_LED\n"
            "    led_driver = &led_driver_dummy;\n"
            "    phy_data.led_driver_present = false;\n"
            "    phy_data.led_driver = PHY_LED_DRIVER_NONE;\n"
            "#endif\n"
            "    if (phy_data.led_driver_present) {"
        )
        patched, count = source.replace("    if (phy_data.led_driver_present) {", injection, 1), 0
        if patched != source:
            count = 1
        if count != 1:
            raise BuildError("Failed to patch LED source. Upstream format may have changed.")

        led_path.write_text(patched, encoding="utf-8")
        return source

    @staticmethod
    def _find_uf2(build_dir: Path) -> Path:
        direct = build_dir / "pico_fido.uf2"
        if direct.exists():
            return direct
        candidates = sorted(build_dir.rglob("*.uf2"), key=lambda p: p.stat().st_mtime, reverse=True)
        if not candidates:
            raise BuildError("Build succeeded but no UF2 file was found.")
        return candidates[0]

    @staticmethod
    def _find_bin(build_dir: Path) -> Path:
        direct = build_dir / "pico_fido.bin"
        if direct.exists():
            return direct
        candidates = sorted(build_dir.rglob("*.bin"), key=lambda p: p.stat().st_mtime, reverse=True)
        if not candidates:
            raise BuildError("Build succeeded but no .bin file was found.")
        return candidates[0]

    @staticmethod
    def _family_id_for_board(board: str) -> int:
        # From Pico SDK: src/common/boot_uf2_headers/include/boot/uf2.h
        if board == "pico":
            return 0xE48BFF56  # RP2040_FAMILY_ID
        if board == "pico2":
            return 0xE48BFF59  # RP2350_ARM_S_FAMILY_ID
        raise BuildError(f"Unsupported board for UF2 family mapping: {board}")

    @staticmethod
    def _bin_to_uf2(bin_path: Path, uf2_path: Path, board: str) -> None:
        data = bin_path.read_bytes()
        payload_size = 256
        total_blocks = (len(data) + payload_size - 1) // payload_size

        magic_start0 = 0x0A324655
        magic_start1 = 0x9E5D5157
        magic_end = 0x0AB16F30
        flag_family_id_present = 0x00002000
        base_addr = 0x10000000
        family_id = FirmwareBuilder._family_id_for_board(board)

        with uf2_path.open("wb") as out:
            for block_no in range(total_blocks):
                offset = block_no * payload_size
                chunk = data[offset : offset + payload_size]
                if len(chunk) < payload_size:
                    chunk = chunk + bytes(payload_size - len(chunk))

                block = bytearray(512)
                # Header words 0..7
                block[0:4] = magic_start0.to_bytes(4, "little")
                block[4:8] = magic_start1.to_bytes(4, "little")
                block[8:12] = flag_family_id_present.to_bytes(4, "little")
                block[12:16] = (base_addr + offset).to_bytes(4, "little")
                block[16:20] = payload_size.to_bytes(4, "little")
                block[20:24] = block_no.to_bytes(4, "little")
                block[24:28] = total_blocks.to_bytes(4, "little")
                block[28:32] = family_id.to_bytes(4, "little")
                # Payload (max 476 bytes in UF2 block, we use 256)
                block[32 : 32 + payload_size] = chunk
                # End magic
                block[512 - 4 : 512] = magic_end.to_bytes(4, "little")
                out.write(block)

    @staticmethod
    def _validate_source_tree(source_dir: Path) -> None:
        if not (source_dir / "CMakeLists.txt").exists():
            raise BuildError("Selected source path is not a pico-fido repository (missing CMakeLists.txt).")

    def prepare_source(self, source_dir: Path, clone_if_missing: bool) -> None:
        if shutil.which("git") is None:
            raise BuildError("`git` is required but not found in PATH.")

        if not source_dir.exists():
            if not clone_if_missing:
                raise BuildError(f"Source path does not exist: {source_dir}")
            source_dir.parent.mkdir(parents=True, exist_ok=True)
            self._run(["git", "clone", UPSTREAM_PICO_FIDO_REPO, str(source_dir)], cwd=source_dir.parent)

        self._validate_source_tree(source_dir)
        self._run(["git", "submodule", "update", "--init", "--recursive"], cwd=source_dir)
        if not (source_dir / DESCRIPTORS_RELATIVE_PATH).exists():
            raise BuildError(
                "Source prepared, but pico-keys-sdk descriptor file was not found. "
                "Check the repository and submodule state."
            )
        if not (source_dir / LED_RELATIVE_PATH).exists():
            raise BuildError(
                "Source prepared, but pico-keys-sdk LED source file was not found. "
                "Check the repository and submodule state."
            )

    def build(self, profile: BuildProfile) -> BuildResult:
        missing = self.missing_dependencies(for_build=True)
        if missing:
            names = ", ".join(self.dependency_display_names().get(dep, dep) for dep in missing)
            raise BuildError(f"Missing dependencies: {names}")

        source_dir = profile.source_path()
        self.prepare_source(source_dir, clone_if_missing=False)

        board = profile.board.strip()
        if board not in {"pico", "pico2"}:
            raise BuildError("Board must be one of: pico, pico2.")

        usb_vid = self._normalize_hex_word(profile.usb_vid, "USB VID")
        usb_pid = self._normalize_hex_word(profile.usb_pid, "USB PID")
        output_uf2 = profile.output_path_or_default(board)
        output_uf2.parent.mkdir(parents=True, exist_ok=True)

        build_dir = source_dir / f"build_openpicokeys_{board}"
        descriptors = source_dir / DESCRIPTORS_RELATIVE_PATH
        led_source = source_dir / LED_RELATIVE_PATH
        original_descriptors = self._patch_descriptors(descriptors, profile)
        original_led_source = self._patch_led(led_source, profile.disable_led)

        env = dict(os.environ)
        pico_sdk_path = profile.sdk_path_or_none()
        if pico_sdk_path is not None:
            env["PICO_SDK_PATH"] = str(pico_sdk_path)

        generator_args: list[str] = []
        if shutil.which("ninja") is not None:
            generator_args = ["-G", "Ninja"]

        try:
            self._run(
                [
                    "cmake",
                    *generator_args,
                    "-S",
                    str(source_dir),
                    "-B",
                    str(build_dir),
                    f"-DPICO_BOARD={board}",
                    f"-DUSB_VID={usb_vid}",
                    f"-DUSB_PID={usb_pid}",
                    "-DPICO_NO_PICOTOOL=1",
                    f"-DOPENPICOKEYS_DISABLE_LED={'1' if profile.disable_led else '0'}",
                ],
                cwd=source_dir,
                env=env,
            )
            self._run(["cmake", "--build", str(build_dir), "--parallel"], cwd=source_dir, env=env)
            built_bin = self._find_bin(build_dir)
            self._bin_to_uf2(built_bin, output_uf2, board)
            self._log(f"UF2 created: {output_uf2}")
            return BuildResult(output_uf2=output_uf2, build_dir=build_dir)
        finally:
            # Always restore upstream descriptors after build attempt.
            descriptors.write_text(original_descriptors, encoding="utf-8")
            led_source.write_text(original_led_source, encoding="utf-8")
