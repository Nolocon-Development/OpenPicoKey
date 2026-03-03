from __future__ import annotations

import os
import platform


def is_admin() -> bool:
    """Return ``True`` when the current process is elevated/root."""
    system = platform.system()
    if system == "Windows":
        try:
            import ctypes

            return bool(ctypes.windll.shell32.IsUserAnAdmin())  # type: ignore[attr-defined]
        except Exception:
            return False

    geteuid = getattr(os, "geteuid", None)
    if callable(geteuid):
        return geteuid() == 0
    return False


def admin_required_message(feature_name: str) -> str:
    return (
        f"{feature_name} requires administrator rights.\n\n"
        "Restart OpenPicoKeys as Administrator to enable backup and restore operations."
    )
