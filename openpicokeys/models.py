from __future__ import annotations

from dataclasses import asdict, dataclass
from pathlib import Path


@dataclass
class BuildProfile:
    source_dir: str = ""
    pico_sdk_path: str = ""
    output_uf2: str = ""
    board: str = "pico"
    key_name: str = "OpenPicoKeys"
    manufacturer: str = "OpenPicoKeys"
    website: str = "www.openpicokeys.local"
    usb_vid: str = "0x2E8A"
    usb_pid: str = "0x10FE"
    disable_led: bool = False

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, payload: dict) -> "BuildProfile":
        # Ignore unknown keys to keep profile loading backward-compatible.
        known = {f.name for f in cls.__dataclass_fields__.values()}
        filtered = {k: v for k, v in payload.items() if k in known}
        return cls(**filtered)

    def source_path(self) -> Path:
        return Path(self.source_dir).expanduser().resolve()

    def sdk_path_or_none(self) -> Path | None:
        if not self.pico_sdk_path.strip():
            return None
        return Path(self.pico_sdk_path).expanduser().resolve()

    def output_path_or_default(self, board_name: str) -> Path:
        if self.output_uf2.strip():
            return Path(self.output_uf2).expanduser().resolve()
        return Path.cwd().resolve() / f"openpicokeys-{board_name}.uf2"
