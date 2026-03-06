from __future__ import annotations

import ctypes
import subprocess
import sys

from openpicokeys.gui import run


def _is_windows_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())  # type: ignore[attr-defined]
    except Exception:
        return False


def _request_uac_elevation() -> bool:
    """Request administrator privileges via UAC and return True when relaunch was started."""
    params = subprocess.list2cmdline(sys.argv)
    result = ctypes.windll.shell32.ShellExecuteW(  # type: ignore[attr-defined]
        None,
        "runas",
        sys.executable,
        params,
        None,
        1,
    )
    return int(result) > 32


if __name__ == "__main__":
    if sys.platform == "win32" and "--noUAC" not in sys.argv and not _is_windows_admin():
        relaunched = _request_uac_elevation()
        # If elevation was requested successfully, end this non-admin instance.
        if relaunched:
            raise SystemExit(0)
        # UAC prompt denied or failed: stop startup to keep admin-only behavior consistent.
        raise SystemExit("Administrator privileges are required. Relaunch with --noUAC to skip UAC request.")

    run()