from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import tempfile
import urllib.request
import zipfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

from .models import BuildProfile


UPSTREAM_PICO_FIDO_REPO = "polhenarejos/pico-fido"
UPSTREAM_PICO_FIDO_REF = "v7.4"
UPSTREAM_PICO_KEYS_REPO = "polhenarejos/pico-keys-sdk"
UPSTREAM_PICO_KEYS_REF = "7abedc5b0e6bf390913b68f5e5f37a997f54a92b"
UPSTREAM_MBEDTLS_REPO = "ARMmbed/mbedtls"
UPSTREAM_MBEDTLS_REF = "107ea89daaefb9867ea9121002fbbdf926780e98"
UPSTREAM_MBEDTLS_FRAMEWORK_REPO = "Mbed-TLS/mbedtls-framework"
UPSTREAM_MBEDTLS_FRAMEWORK_REF = "94599c0e3b5036e086446a51a3f79640f70f22f6"
UPSTREAM_MLKEM_REPO = "pq-code-package/mlkem-native"
UPSTREAM_MLKEM_REF = "1453da5cd11ea6be7ae83d619d1a72b21e48ec7d"
UPSTREAM_TINYCBOR_REPO = "intel/tinycbor"
UPSTREAM_TINYCBOR_REF = "c0aad2fb2137a31b9845fbaae3653540c410f215"
UPSTREAM_PICO_SDK_REPO = "raspberrypi/pico-sdk"
UPSTREAM_PICO_SDK_REF = "2.2.0"
UPSTREAM_PICO_SDK_SUBMODULE_FALLBACK_REFS = {
    "lib/tinyusb": "86ad6e56c1700e85f1c5678607a762cfe3aa2f47",
    "lib/cyw43-driver": "dd7568229f3bf7a37737b9e1ef250c26efe75b23",
    "lib/lwip": "77dcd25a72509eb83f72b033d219b1d40cd8eb95",
    "lib/mbedtls": "107ea89daaefb9867ea9121002fbbdf926780e98",
    "lib/btstack": "501e6d2b86e6c92bfb9c390bcf55709938e25ac1",
}

DESCRIPTORS_RELATIVE_PATH = Path("pico-keys-sdk/src/usb/usb_descriptors.c")
LED_RELATIVE_PATH = Path("pico-keys-sdk/src/led/led.c")
MANAGED_ROOT = Path.home() / ".openpicokeys" / "resources"
MANIFEST_FILENAME = ".openpicokeys-manifest.json"


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
            "ninja": [
                [
                    "winget",
                    "install",
                    "--id",
                    "Ninja-build.Ninja",
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
            "cmake": "CMake",
            "ninja": "Ninja",
            "arm-none-eabi-gcc": "GNU Arm Embedded Toolchain",
        }

    @classmethod
    def required_dependencies(cls, for_build: bool) -> list[str]:
        if for_build:
            return ["cmake", "ninja", "arm-none-eabi-gcc"]
        return []

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
    def _codeload_url(repo_slug: str, ref: str) -> str:
        return f"https://codeload.github.com/{repo_slug}/zip/{ref}"

    @staticmethod
    def _load_manifest(path: Path) -> dict | None:
        manifest_path = path / MANIFEST_FILENAME
        if not manifest_path.exists():
            return None
        try:
            return json.loads(manifest_path.read_text(encoding="utf-8"))
        except Exception:
            return None

    @staticmethod
    def _write_manifest(path: Path, repo_slug: str, ref: str) -> None:
        manifest_path = path / MANIFEST_FILENAME
        payload = {
            "repo": repo_slug,
            "ref": ref,
            "fetched_at_utc": datetime.now(timezone.utc).isoformat(),
        }
        manifest_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    def _download_repo_archive(self, repo_slug: str, ref: str, target_dir: Path) -> None:
        self._log(f"Downloading {repo_slug}@{ref}...")
        target_dir.parent.mkdir(parents=True, exist_ok=True)

        with tempfile.TemporaryDirectory(dir=str(target_dir.parent)) as tmp:
            tmp_dir = Path(tmp)
            zip_path = tmp_dir / "archive.zip"
            url = self._codeload_url(repo_slug, ref)
            req = urllib.request.Request(
                url,
                headers={
                    "User-Agent": "OpenPicoKeys/1.0",
                    "Accept": "application/zip",
                },
            )
            with urllib.request.urlopen(req, timeout=120) as response, zip_path.open("wb") as out:
                shutil.copyfileobj(response, out)

            with zipfile.ZipFile(zip_path, "r") as archive:
                archive.extractall(tmp_dir / "extract")

            extracted_root_candidates = [p for p in (tmp_dir / "extract").iterdir() if p.is_dir()]
            if len(extracted_root_candidates) != 1:
                raise BuildError(f"Unexpected archive layout for {repo_slug}@{ref}.")
            extracted_root = extracted_root_candidates[0]

            if target_dir.exists():
                shutil.rmtree(target_dir)
            shutil.move(str(extracted_root), str(target_dir))
            self._write_manifest(target_dir, repo_slug, ref)
            self._log(f"Fetched resource: {target_dir}")

    @staticmethod
    def _repo_slug_from_git_url(url: str, base_repo_slug: str | None = None) -> str:
        cleaned = url.strip()
        if cleaned.startswith("git@github.com:"):
            cleaned = cleaned.split(":", 1)[1]
        if cleaned.endswith(".git"):
            cleaned = cleaned[:-4]
        prefix = "https://github.com/"
        if cleaned.startswith(prefix):
            return cleaned[len(prefix) :]
        if cleaned.startswith("../") or cleaned.startswith("./"):
            if not base_repo_slug:
                return cleaned
            parts = base_repo_slug.split("/")
            for token in cleaned.split("/"):
                if token in {"", "."}:
                    continue
                if token == "..":
                    if parts:
                        parts.pop()
                    continue
                parts.append(token)
            return "/".join(parts)
        return cleaned

    def _github_json(self, url: str) -> dict:
        req = urllib.request.Request(
            url,
            headers={
                "User-Agent": "OpenPicoKeys/1.0",
                "Accept": "application/vnd.github+json",
            },
        )
        with urllib.request.urlopen(req, timeout=120) as response:
            return json.loads(response.read().decode("utf-8"))

    def _sdk_submodule_shas(self) -> dict[str, str]:
        tree_url = f"https://api.github.com/repos/{UPSTREAM_PICO_SDK_REPO}/git/trees/{UPSTREAM_PICO_SDK_REF}?recursive=1"
        payload = self._github_json(tree_url)
        shas: dict[str, str] = {}
        for entry in payload.get("tree", []):
            if entry.get("mode") == "160000":
                path = entry.get("path")
                sha = entry.get("sha")
                if path and sha:
                    shas[path] = sha
        return shas

    def _sdk_submodule_specs(self, sdk_dir: Path) -> list[tuple[str, str]]:
        modules_path = sdk_dir / ".gitmodules"
        if not modules_path.exists():
            return []
        specs: list[tuple[str, str]] = []
        current_path = ""
        current_url = ""
        for raw in modules_path.read_text(encoding="utf-8").splitlines():
            line = raw.strip()
            if line.startswith("[submodule "):
                if current_path and current_url:
                    specs.append((current_path, current_url))
                current_path = ""
                current_url = ""
                continue
            if line.startswith("path = "):
                current_path = line.split("=", 1)[1].strip()
            elif line.startswith("url = "):
                current_url = line.split("=", 1)[1].strip()
        if current_path and current_url:
            specs.append((current_path, current_url))
        return specs

    def _ensure_pico_sdk_submodules(self, sdk_dir: Path) -> None:
        specs = self._sdk_submodule_specs(sdk_dir)
        if not specs:
            return

        shas: dict[str, str] = {}
        try:
            shas = self._sdk_submodule_shas()
        except Exception as exc:
            self._log(f"Warning: could not query pico-sdk submodule SHAs from GitHub API: {exc}")
            self._log("Falling back to predefined refs for pico-sdk submodules.")

        marker_map = {
            "lib/tinyusb": "src/tusb.c",
            "lib/cyw43-driver": "README.md",
            "lib/lwip": "README",
            "lib/mbedtls": "CMakeLists.txt",
            "lib/btstack": "README.md",
        }
        for path, url in specs:
            repo_slug = self._repo_slug_from_git_url(url, UPSTREAM_PICO_SDK_REPO)
            ref = shas.get(path) or UPSTREAM_PICO_SDK_SUBMODULE_FALLBACK_REFS.get(path) or "master"
            marker = marker_map.get(path, "README.md")
            self._ensure_repo_at(
                sdk_dir / path,
                repo_slug,
                ref,
                marker_relative_path=marker,
            )

    def _ensure_repo_at(
        self,
        target_dir: Path,
        repo_slug: str,
        ref: str,
        marker_relative_path: str | None = None,
        force: bool = False,
    ) -> None:
        manifest = self._load_manifest(target_dir)
        marker_ok = (target_dir / marker_relative_path).exists() if marker_relative_path else target_dir.exists()
        if not force and target_dir.exists() and manifest is None and marker_ok:
            self._log(f"Using existing directory: {target_dir}")
            return
        if (
            not force
            and target_dir.exists()
            and manifest is not None
            and manifest.get("repo") == repo_slug
            and manifest.get("ref") == ref
            and marker_ok
        ):
            self._log(f"Using cached resource: {repo_slug}@{ref}")
            return

        self._download_repo_archive(repo_slug, ref, target_dir)

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
            "    led_driver = &led_driver_dummy;\n"
            "    phy_data.led_driver_present = false;\n"
            "    phy_data.led_driver = PHY_LED_DRIVER_NONE;\n"
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

    def _ensure_pico_fido_tree(self, source_dir: Path) -> None:
        self._ensure_repo_at(
            source_dir,
            UPSTREAM_PICO_FIDO_REPO,
            UPSTREAM_PICO_FIDO_REF,
            marker_relative_path="CMakeLists.txt",
        )
        self._ensure_repo_at(
            source_dir / "pico-keys-sdk",
            UPSTREAM_PICO_KEYS_REPO,
            UPSTREAM_PICO_KEYS_REF,
            marker_relative_path="src/usb/usb_descriptors.c",
        )
        self._ensure_repo_at(
            source_dir / "pico-keys-sdk" / "mbedtls",
            UPSTREAM_MBEDTLS_REPO,
            UPSTREAM_MBEDTLS_REF,
            marker_relative_path="CMakeLists.txt",
        )
        self._ensure_repo_at(
            source_dir / "pico-keys-sdk" / "mbedtls" / "framework",
            UPSTREAM_MBEDTLS_FRAMEWORK_REPO,
            UPSTREAM_MBEDTLS_FRAMEWORK_REF,
            marker_relative_path="README.md",
        )
        self._ensure_repo_at(
            source_dir / "pico-keys-sdk" / "mlkem",
            UPSTREAM_MLKEM_REPO,
            UPSTREAM_MLKEM_REF,
            marker_relative_path="CMakeLists.txt",
        )
        self._ensure_repo_at(
            source_dir / "pico-keys-sdk" / "tinycbor",
            UPSTREAM_TINYCBOR_REPO,
            UPSTREAM_TINYCBOR_REF,
            marker_relative_path="src/cbor.h",
        )

    def ensure_pico_sdk(self) -> Path:
        sdk_dir = MANAGED_ROOT / "pico-sdk"
        self._ensure_repo_at(
            sdk_dir,
            UPSTREAM_PICO_SDK_REPO,
            UPSTREAM_PICO_SDK_REF,
            marker_relative_path="pico_sdk_init.cmake",
        )
        self._ensure_pico_sdk_submodules(sdk_dir)
        if not (sdk_dir / "pico_sdk_init.cmake").exists():
            raise BuildError("Managed pico-sdk download is incomplete (missing pico_sdk_init.cmake).")
        return sdk_dir

    @staticmethod
    def default_source_dir() -> Path:
        return MANAGED_ROOT / "pico-fido"

    def prepare_source(self, source_dir: Path, clone_if_missing: bool) -> None:
        if not source_dir.exists() and not clone_if_missing:
            raise BuildError(f"Source path does not exist: {source_dir}")

        source_dir.parent.mkdir(parents=True, exist_ok=True)
        self._ensure_pico_fido_tree(source_dir)
        self._validate_source_tree(source_dir)
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
        self.prepare_source(source_dir, clone_if_missing=True)

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
        if pico_sdk_path is None:
            pico_sdk_path = self.ensure_pico_sdk()
            self._log(f"Using managed pico-sdk at: {pico_sdk_path}")
        elif not pico_sdk_path.exists():
            raise BuildError(f"PICO_SDK_PATH does not exist: {pico_sdk_path}")
        env["PICO_SDK_PATH"] = str(pico_sdk_path)

        try:
            self._run(
                [
                    "cmake",
                    "-G",
                    "Ninja",
                    "-S",
                    str(source_dir),
                    "-B",
                    str(build_dir),
                    f"-DPICO_BOARD={board}",
                    f"-DUSB_VID={usb_vid}",
                    f"-DUSB_PID={usb_pid}",
                    "-DPICO_NO_PICOTOOL=1",
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
