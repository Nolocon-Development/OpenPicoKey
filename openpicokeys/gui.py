from __future__ import annotations

import json
import os
import queue
import re
import subprocess
import sys
import threading
import traceback
import tkinter as tk
import ctypes
from base64 import b64decode, b64encode
from base64 import urlsafe_b64encode
from datetime import datetime, timezone
from pathlib import Path
from tkinter import filedialog, messagebox, scrolledtext, simpledialog, ttk

from .builder import BuildError, FirmwareBuilder
from .models import BuildProfile


class ElevationRequiredError(BuildError):
    pass


class OpenPicoKeysApp(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title("OpenPicoKeys")
        self.geometry("980x760")
        self.minsize(900, 700)

        self._events: queue.Queue[tuple[str, object]] = queue.Queue()
        self._worker: threading.Thread | None = None
        self._busy = False
        self._reader_devices_by_label: dict[str, str] = {}
        self._reader_device_mode_by_fingerprint: dict[str, str] = {}
        self._key_reader_device_combo: ttk.Combobox | None = None
        self._notebook: ttk.Notebook | None = None

        default_source = str(FirmwareBuilder.default_source_dir())

        self.source_var = tk.StringVar(value=default_source)
        self.sdk_var = tk.StringVar(value="")
        self.output_var = tk.StringVar(value=str((Path.cwd() / "openpicokeys-pico.uf2").resolve()))
        self.board_var = tk.StringVar(value="pico")
        self.key_name_var = tk.StringVar(value="OpenPicoKeys")
        self.manufacturer_var = tk.StringVar(value="OpenPicoKeys")
        self.website_var = tk.StringVar(value="www.openpicokeys.local")
        self.usb_vid_var = tk.StringVar(value="0x2E8A")
        self.usb_pid_var = tk.StringVar(value="0x10FE")
        self.disable_led_var = tk.BooleanVar(value=False)
        self.reader_device_var = tk.StringVar(value="")
        self.reader_pin_var = tk.StringVar(value="")
        self.reader_scope_var = tk.StringVar(value="Currently Selected Key")
        self.status_var = tk.StringVar(value="Ready")

        self._interactive_widgets: list[tk.Widget] = []
        self._build_ui()
        self.after(100, self._drain_events)
        self.after(300, self._check_dependencies_on_startup)

    def _build_ui(self) -> None:
        root = ttk.Frame(self, padding=12)
        root.grid(sticky="nsew")
        self.columnconfigure(0, weight=1)
        self.rowconfigure(0, weight=1)
        root.columnconfigure(0, weight=1)
        root.rowconfigure(1, weight=1)

        header = ttk.Label(
            root,
            text="OpenPicoKeys - Open source PicoKey alternative (Tkinter)",
            font=("Segoe UI", 13, "bold"),
        )
        header.grid(row=0, column=0, sticky="w")

        notebook = ttk.Notebook(root)
        notebook.grid(row=1, column=0, sticky="nsew", pady=(10, 0))
        self._notebook = notebook
        notebook.bind("<<NotebookTabChanged>>", self._on_tab_changed)

        firmware_tab = ttk.Frame(notebook)
        key_customizer_tab = ttk.Frame(notebook)
        key_reader_tab = ttk.Frame(notebook)
        notebook.add(firmware_tab, text="Firmware Builder")
        notebook.add(key_customizer_tab, text="Key customizer")
        notebook.add(key_reader_tab, text="Key Reader")

        firmware_tab.columnconfigure(0, weight=1)
        firmware_tab.rowconfigure(0, weight=1)
        builder_root = ttk.Frame(firmware_tab, padding=8)
        builder_root.grid(row=0, column=0, sticky="nsew")
        builder_root.columnconfigure(0, weight=1)
        builder_root.rowconfigure(3, weight=1)

        subtitle = ttk.Label(
            builder_root,
            text="Step 1: Source setup  |  Step 2: Customize name + website  |  Step 3: Build .uf2",
        )
        subtitle.grid(row=0, column=0, sticky="w", pady=(2, 12))

        source_frame = ttk.LabelFrame(builder_root, text="Step 1 - Pico FIDO Source")
        source_frame.grid(row=1, column=0, sticky="ew")
        source_frame.columnconfigure(1, weight=1)
        source_frame.columnconfigure(3, weight=0)

        ttk.Label(source_frame, text="Source path").grid(row=0, column=0, padx=6, pady=6, sticky="w")
        source_entry = ttk.Entry(source_frame, textvariable=self.source_var)
        source_entry.grid(row=0, column=1, padx=6, pady=6, sticky="ew")
        source_browse = ttk.Button(source_frame, text="Browse", command=self._pick_source_dir)
        source_browse.grid(row=0, column=2, padx=6, pady=6, sticky="ew")
        source_prepare = ttk.Button(source_frame, text="Prepare Source", command=self._on_prepare_source)
        source_prepare.grid(row=0, column=3, padx=6, pady=6, sticky="ew")

        ttk.Label(source_frame, text="PICO_SDK_PATH (optional)").grid(
            row=1, column=0, padx=6, pady=6, sticky="w"
        )
        sdk_entry = ttk.Entry(source_frame, textvariable=self.sdk_var)
        sdk_entry.grid(row=1, column=1, padx=6, pady=6, sticky="ew")
        sdk_browse = ttk.Button(source_frame, text="Browse", command=self._pick_sdk_dir)
        sdk_browse.grid(row=1, column=2, padx=6, pady=6, sticky="ew")

        profile_frame = ttk.LabelFrame(builder_root, text="Step 2 - Device Customization")
        profile_frame.grid(row=2, column=0, sticky="ew", pady=(12, 0))
        for col in range(4):
            profile_frame.columnconfigure(col, weight=1)

        ttk.Label(profile_frame, text="Key Name (USB product)").grid(row=0, column=0, padx=6, pady=6, sticky="w")
        key_name_entry = ttk.Entry(profile_frame, textvariable=self.key_name_var)
        key_name_entry.grid(row=0, column=1, padx=6, pady=6, sticky="ew")

        ttk.Label(profile_frame, text="Manufacturer").grid(row=0, column=2, padx=6, pady=6, sticky="w")
        manufacturer_entry = ttk.Entry(profile_frame, textvariable=self.manufacturer_var)
        manufacturer_entry.grid(row=0, column=3, padx=6, pady=6, sticky="ew")

        ttk.Label(profile_frame, text="Website (WebUSB)").grid(row=1, column=0, padx=6, pady=6, sticky="w")
        website_entry = ttk.Entry(profile_frame, textvariable=self.website_var)
        website_entry.grid(row=1, column=1, padx=6, pady=6, sticky="ew")

        ttk.Label(profile_frame, text="Board").grid(row=1, column=2, padx=6, pady=6, sticky="w")
        board_combo = ttk.Combobox(
            profile_frame,
            textvariable=self.board_var,
            values=["pico", "pico2"],
            state="readonly",
        )
        board_combo.grid(row=1, column=3, padx=6, pady=6, sticky="ew")

        ttk.Label(profile_frame, text="USB VID").grid(row=2, column=0, padx=6, pady=6, sticky="w")
        vid_entry = ttk.Entry(profile_frame, textvariable=self.usb_vid_var)
        vid_entry.grid(row=2, column=1, padx=6, pady=6, sticky="ew")

        ttk.Label(profile_frame, text="USB PID").grid(row=2, column=2, padx=6, pady=6, sticky="w")
        pid_entry = ttk.Entry(profile_frame, textvariable=self.usb_pid_var)
        pid_entry.grid(row=2, column=3, padx=6, pady=6, sticky="ew")

        disable_led_check = ttk.Checkbutton(
            profile_frame,
            text="Disable LED on Pico firmware",
            variable=self.disable_led_var,
        )
        disable_led_check.grid(row=3, column=0, columnspan=2, padx=6, pady=6, sticky="w")

        ttk.Label(profile_frame, text="Output UF2").grid(row=4, column=0, padx=6, pady=6, sticky="w")
        output_entry = ttk.Entry(profile_frame, textvariable=self.output_var)
        output_entry.grid(row=4, column=1, padx=6, pady=6, sticky="ew")
        output_browse = ttk.Button(profile_frame, text="Browse", command=self._pick_output_file)
        output_browse.grid(row=4, column=2, padx=6, pady=6, sticky="ew")

        action_frame = ttk.Frame(profile_frame)
        action_frame.grid(row=4, column=3, padx=6, pady=6, sticky="e")
        save_button = ttk.Button(action_frame, text="Save Profile", command=self._save_profile)
        save_button.grid(row=0, column=0, padx=(0, 6))
        load_button = ttk.Button(action_frame, text="Load Profile", command=self._load_profile)
        load_button.grid(row=0, column=1, padx=(0, 6))
        build_button = ttk.Button(action_frame, text="Build UF2", command=self._on_build)
        build_button.grid(row=0, column=2)

        logs_frame = ttk.LabelFrame(builder_root, text="Step 3 - Build Logs")
        logs_frame.grid(row=3, column=0, sticky="nsew", pady=(12, 0))
        logs_frame.columnconfigure(0, weight=1)
        logs_frame.rowconfigure(0, weight=1)

        self.logs = scrolledtext.ScrolledText(logs_frame, wrap=tk.WORD, height=20)
        self.logs.grid(row=0, column=0, sticky="nsew")
        self.logs.configure(state="disabled")

        status_frame = ttk.Frame(builder_root)
        status_frame.grid(row=4, column=0, sticky="ew", pady=(8, 0))
        status_frame.columnconfigure(0, weight=1)
        status_label = ttk.Label(status_frame, textvariable=self.status_var)
        status_label.grid(row=0, column=0, sticky="w")

        key_customizer_tab.columnconfigure(0, weight=1)
        key_customizer_tab.rowconfigure(0, weight=1)
        ttk.Label(
            key_customizer_tab,
            text="Key customizer placeholder.\nThis tab will host key customization tools.",
            justify="center",
        ).grid(row=0, column=0, sticky="nsew", padx=16, pady=16)

        key_reader_tab.columnconfigure(0, weight=1)
        key_reader_tab.rowconfigure(0, weight=1)
        key_reader_root = ttk.Frame(key_reader_tab, padding=10)
        key_reader_root.grid(row=0, column=0, sticky="nsew")
        key_reader_root.columnconfigure(0, weight=1)
        key_reader_root.rowconfigure(2, weight=1)

        key_reader_controls = ttk.LabelFrame(key_reader_root, text="FIDO Key Reader")
        key_reader_controls.grid(row=0, column=0, sticky="ew")
        key_reader_controls.columnconfigure(1, weight=1)

        ttk.Label(key_reader_controls, text="Security key").grid(row=0, column=0, padx=6, pady=6, sticky="w")
        key_reader_device_combo = ttk.Combobox(
            key_reader_controls,
            textvariable=self.reader_device_var,
            state="readonly",
        )
        key_reader_device_combo.grid(row=0, column=1, padx=6, pady=6, sticky="ew")
        self._key_reader_device_combo = key_reader_device_combo
        key_reader_refresh_button = ttk.Button(
            key_reader_controls,
            text="Refresh Devices",
            command=self._on_refresh_key_devices,
        )
        key_reader_refresh_button.grid(row=0, column=2, padx=6, pady=6, sticky="ew")

        ttk.Label(key_reader_controls, text="PIN").grid(row=1, column=0, padx=6, pady=6, sticky="w")
        key_reader_pin_entry = ttk.Entry(
            key_reader_controls,
            textvariable=self.reader_pin_var,
            show="*",
        )
        key_reader_pin_entry.grid(row=1, column=1, padx=6, pady=6, sticky="ew")
        key_reader_read_button = ttk.Button(
            key_reader_controls,
            text="Read Key Content",
            command=self._on_read_key_data,
        )
        key_reader_read_button.grid(row=1, column=2, padx=6, pady=6, sticky="ew")

        ttk.Label(key_reader_controls, text="Scope").grid(row=2, column=0, padx=6, pady=6, sticky="w")
        key_reader_scope_combo = ttk.Combobox(
            key_reader_controls,
            textvariable=self.reader_scope_var,
            values=["Currently Selected Key", "All-Keys"],
            state="readonly",
        )
        key_reader_scope_combo.grid(row=2, column=1, padx=6, pady=6, sticky="ew")
        scope_actions = ttk.Frame(key_reader_controls)
        scope_actions.grid(row=2, column=2, padx=6, pady=6, sticky="e")
        key_reader_backup_button = ttk.Button(
            scope_actions,
            text="Backup Key(s)",
            command=self._on_backup_keys,
        )
        key_reader_backup_button.grid(row=0, column=0, padx=(0, 6))
        key_reader_load_button = ttk.Button(
            scope_actions,
            text="Load Key(s)",
            command=self._on_load_keys,
        )
        key_reader_load_button.grid(row=0, column=1)

        ttk.Label(
            key_reader_root,
            text="Reads FIDO2 authenticator info and resident credentials (where supported).",
        ).grid(row=1, column=0, sticky="w", pady=(8, 6))

        key_reader_output_frame = ttk.LabelFrame(key_reader_root, text="Key Reader Output")
        key_reader_output_frame.grid(row=2, column=0, sticky="nsew")
        key_reader_output_frame.columnconfigure(0, weight=1)
        key_reader_output_frame.rowconfigure(0, weight=1)
        self.key_reader_output = scrolledtext.ScrolledText(key_reader_output_frame, wrap=tk.WORD, height=16)
        self.key_reader_output.grid(row=0, column=0, sticky="nsew")
        self.key_reader_output.configure(state="disabled")

        self._interactive_widgets = [
            source_entry,
            source_browse,
            source_prepare,
            sdk_entry,
            sdk_browse,
            key_name_entry,
            manufacturer_entry,
            website_entry,
            board_combo,
            vid_entry,
            pid_entry,
            output_entry,
            output_browse,
            disable_led_check,
            save_button,
            load_button,
            build_button,
            key_reader_device_combo,
            key_reader_refresh_button,
            key_reader_pin_entry,
            key_reader_read_button,
            key_reader_scope_combo,
            key_reader_backup_button,
            key_reader_load_button,
        ]

    def _append_log(self, message: str) -> None:
        view_before = self.logs.yview()
        at_bottom = view_before[1] >= 0.999
        self.logs.configure(state="normal")
        self.logs.insert(tk.END, message.rstrip() + "\n")
        if at_bottom:
            self.logs.see(tk.END)
        else:
            self.logs.yview_moveto(view_before[0])
        self.logs.configure(state="disabled")

    def _append_key_reader_output(self, message: str) -> None:
        view_before = self.key_reader_output.yview()
        at_bottom = view_before[1] >= 0.999
        self.key_reader_output.configure(state="normal")
        self.key_reader_output.insert(tk.END, message.rstrip() + "\n")
        if at_bottom:
            self.key_reader_output.see(tk.END)
        else:
            self.key_reader_output.yview_moveto(view_before[0])
        self.key_reader_output.configure(state="disabled")

    def _post(self, kind: str, payload: object) -> None:
        self._events.put((kind, payload))

    def _drain_events(self) -> None:
        while True:
            try:
                kind, payload = self._events.get_nowait()
            except queue.Empty:
                break

            if kind == "log":
                self._append_log(str(payload))
            elif kind == "reader_log":
                self._append_key_reader_output(str(payload))
            elif kind == "status":
                self.status_var.set(str(payload))
            elif kind == "error":
                self.status_var.set("Failed")
                self._append_log(f"[ERROR] {payload}")
                messagebox.showerror("OpenPicoKeys", str(payload))
            elif kind == "success":
                self.status_var.set(str(payload))
            elif kind == "done":
                self._set_busy(False)
            elif kind == "info":
                messagebox.showinfo("OpenPicoKeys", str(payload))
            elif kind == "startup_dep_check":
                self.after(100, self._check_dependencies_on_startup)
            elif kind == "restart":
                self._restart_app()
            elif kind == "reader_devices":
                labels = payload if isinstance(payload, list) else []
                self._apply_key_reader_devices(labels)
            elif kind == "elevate_admin":
                reason = str(payload)
                self._request_admin_for_key_reader(reason)

        self.after(100, self._drain_events)

    def _set_busy(self, busy: bool) -> None:
        self._busy = busy
        state = "disabled" if busy else "normal"
        for widget in self._interactive_widgets:
            if isinstance(widget, ttk.Combobox):
                widget.configure(state="disabled" if busy else "readonly")
                continue
            widget.configure(state=state)
        if busy:
            self.status_var.set("Working...")
        elif self.status_var.get() == "Working...":
            self.status_var.set("Ready")

    def _start_background(self, worker) -> None:
        if self._worker is not None and self._worker.is_alive():
            messagebox.showwarning("OpenPicoKeys", "A task is already running.")
            return

        def runner() -> None:
            try:
                worker()
            except ElevationRequiredError as exc:
                self._post("elevate_admin", str(exc))
            except BuildError as exc:
                self._post("error", str(exc))
            except Exception as exc:  # pragma: no cover - defensive UI exception path
                detail = f"Unexpected error: {exc}\n\n{traceback.format_exc()}"
                self._post("error", detail)
            finally:
                self._post("done", "")

        self._set_busy(True)
        self._worker = threading.Thread(target=runner, daemon=True)
        self._worker.start()

    def _pick_source_dir(self) -> None:
        selected = filedialog.askdirectory(title="Select pico-fido source directory")
        if selected:
            self.source_var.set(selected)

    def _pick_sdk_dir(self) -> None:
        selected = filedialog.askdirectory(title="Select Pico SDK path")
        if selected:
            self.sdk_var.set(selected)

    def _pick_output_file(self) -> None:
        selected = filedialog.asksaveasfilename(
            title="Choose output UF2 file",
            defaultextension=".uf2",
            filetypes=[("UF2 firmware", "*.uf2"), ("All files", "*.*")],
        )
        if selected:
            self.output_var.set(selected)

    def _collect_profile(self) -> BuildProfile:
        profile = BuildProfile(
            source_dir=self.source_var.get().strip(),
            pico_sdk_path=self.sdk_var.get().strip(),
            output_uf2=self.output_var.get().strip(),
            board=self.board_var.get().strip(),
            key_name=self.key_name_var.get().strip(),
            manufacturer=self.manufacturer_var.get().strip(),
            website=self.website_var.get().strip(),
            usb_vid=self.usb_vid_var.get().strip(),
            usb_pid=self.usb_pid_var.get().strip(),
            disable_led=self.disable_led_var.get(),
        )
        if not profile.source_dir:
            raise BuildError("Source path is required.")
        return profile

    def _check_dependencies_on_startup(self) -> None:
        if self._busy:
            return
        missing = FirmwareBuilder.missing_dependencies(for_build=True)
        if not missing:
            return

        display_names = [
            FirmwareBuilder.dependency_display_names().get(dependency, dependency) for dependency in missing
        ]
        dependency_summary = "\n".join(f"- {name}" for name in display_names)
        install_now = messagebox.askyesno(
            "Missing Dependency",
            "OpenPicoKeys requires these missing dependencies to build firmware:\n\n"
            f"{dependency_summary}\n\n"
            "Do you want OpenPicoKeys to auto-install all of them now?",
        )
        if not install_now:
            self.status_var.set("Missing dependencies")
            return

        def worker() -> None:
            builder = FirmwareBuilder(log_callback=lambda line: self._post("log", line))
            self._post("status", "Installing missing dependencies...")
            for dependency in missing:
                builder.install_dependency(dependency)
            self._post("success", "Dependencies installed")
            self._post("restart", "")

        self._start_background(worker)

    def _restart_app(self) -> None:
        self._append_log("Restarting OpenPicoKeys to refresh environment...")
        self.update_idletasks()
        os.execv(sys.executable, [sys.executable, *sys.argv])

    @staticmethod
    def _is_windows_admin() -> bool:
        if not sys.platform.startswith("win"):
            return False
        try:
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False

    def _request_admin_for_key_reader(self, reason: str) -> None:
        if not sys.platform.startswith("win"):
            messagebox.showerror("OpenPicoKeys", reason)
            return
        if self._is_windows_admin():
            messagebox.showerror("OpenPicoKeys", reason)
            return

        elevate_now = messagebox.askyesno(
            "Administrator Required",
            f"{reason}\n\n"
            "OpenPicoKeys can restart with Administrator rights now to retry key reading.\n\n"
            "Restart as Administrator?",
        )
        if not elevate_now:
            self.status_var.set("Reader blocked by permissions")
            return

        args = subprocess.list2cmdline(sys.argv)
        result = ctypes.windll.shell32.ShellExecuteW(
            None,
            "runas",
            sys.executable,
            args,
            None,
            1,
        )
        if int(result) <= 32:
            messagebox.showerror(
                "OpenPicoKeys",
                "Failed to elevate process. Run OpenPicoKeys manually as Administrator and try again.",
            )
            return
        self.destroy()

    def _ensure_python_module(
        self,
        module_name: str,
        package_name: str,
        display_name: str,
        reason: str,
        prompt_if_missing: bool = True,
    ) -> bool:
        try:
            __import__(module_name)
            return True
        except ImportError:
            pass

        if not prompt_if_missing:
            return False

        install_now = messagebox.askyesno(
            "Missing Dependency",
            f"{display_name} is not installed, so OpenPicoKeys cannot {reason}.\n\n"
            f"Do you want OpenPicoKeys to auto-install {display_name} now?",
        )
        if not install_now:
            return False

        def worker() -> None:
            self._post("status", f"Installing {display_name}...")
            self._post("log", f"$ {sys.executable} -m pip install {package_name}")
            proc = subprocess.Popen(
                [sys.executable, "-m", "pip", "install", package_name],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
            )
            assert proc.stdout is not None
            for line in proc.stdout:
                self._post("log", line.rstrip())
            rc = proc.wait()
            if rc != 0:
                raise BuildError(f"Failed to install {display_name} (exit code {rc}).")
            self._post("success", f"{display_name} installed")
            self._post("restart", "")

        self._start_background(worker)
        return False

    @staticmethod
    def _format_device_label(device) -> tuple[str, str]:
        descriptor = getattr(device, "descriptor", None)
        path = str(getattr(descriptor, "path", ""))
        vid = getattr(descriptor, "vendor_id", None)
        pid = getattr(descriptor, "product_id", None)
        product_name = getattr(descriptor, "product_name", "") or "Unknown key"
        serial_number = getattr(descriptor, "serial_number", "") or ""
        fingerprint = f"{path}|{vid}|{pid}|{serial_number}"
        vidpid = ""
        if isinstance(vid, int) and isinstance(pid, int):
            vidpid = f"{vid:04X}:{pid:04X}"
        label_parts = [product_name]
        if vidpid:
            label_parts.append(f"[{vidpid}]")
        if serial_number:
            label_parts.append(f"SN:{serial_number}")
        label_parts.append(path or "path:unknown")
        label = " ".join(part for part in label_parts if part)
        return label, fingerprint

    def _list_key_reader_devices(self) -> list[tuple[str, str]]:
        from fido2.hid import CtapHidDevice, list_descriptors, open_device

        formatted: list[tuple[str, str]] = []
        seen: set[str] = set()

        for device in CtapHidDevice.list_devices():
            label, fingerprint = self._format_device_label(device)
            if fingerprint in seen:
                continue
            seen.add(fingerprint)
            formatted.append((label, fingerprint))

        # Fallback path: explicitly enumerate HID descriptors then try opening each.
        # Some Windows setups miss devices in list_devices() but can still open by path.
        for descriptor in list_descriptors():
            path = getattr(descriptor, "path", None)
            if path is None:
                continue
            try:
                device = open_device(path)
            except Exception:
                continue
            label, fingerprint = self._format_device_label(device)
            if fingerprint in seen:
                continue
            seen.add(fingerprint)
            formatted.append((label, fingerprint))

        for label, fingerprint in self._list_windows_pico_fido_fallback_devices():
            if fingerprint in seen:
                continue
            seen.add(fingerprint)
            formatted.append((label, fingerprint))

        return formatted

    @staticmethod
    def _list_windows_pico_fido_fallback_devices() -> list[tuple[str, str]]:
        if not sys.platform.startswith("win"):
            return []

        script = (
            "$items = Get-PnpDevice -PresentOnly | "
            "Where-Object { $_.InstanceId -match '^HID\\\\VID_2E8A&PID_[0-9A-F]{4}&MI_00' } | "
            "Select-Object FriendlyName,InstanceId; "
            "$items | ConvertTo-Json -Compress"
        )
        proc = subprocess.run(
            ["powershell", "-NoProfile", "-Command", script],
            capture_output=True,
            text=True,
            check=False,
        )
        if proc.returncode != 0:
            return []
        text = proc.stdout.strip()
        if not text:
            return []
        try:
            payload = json.loads(text)
        except Exception:
            return []

        entries = payload if isinstance(payload, list) else [payload]
        result: list[tuple[str, str]] = []
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            instance_id = str(entry.get("InstanceId", "")).strip()
            if not instance_id:
                continue
            friendly_name = str(entry.get("FriendlyName", "")).strip() or "Raspberry Pi Pico FIDO"
            vidpid_match = re.search(r"VID_([0-9A-F]{4})&PID_([0-9A-F]{4})", instance_id, re.IGNORECASE)
            vidpid = ""
            if vidpid_match:
                vidpid = f"{vidpid_match.group(1).upper()}:{vidpid_match.group(2).upper()}"
            label = f"{friendly_name} [PnP fallback]{f' [{vidpid}]' if vidpid else ''}"
            fingerprint = f"pnp::{instance_id}"
            result.append((label, fingerprint))
        return result

    def _apply_key_reader_devices(self, device_rows: list[tuple[str, str]]) -> None:
        labels = [label for label, _ in device_rows]
        self._reader_devices_by_label = {label: fingerprint for label, fingerprint in device_rows}
        self._reader_device_mode_by_fingerprint = {
            fingerprint: ("pnp_fallback" if fingerprint.startswith("pnp::") else "ctap")
            for _, fingerprint in device_rows
        }
        if self._key_reader_device_combo is not None:
            self._key_reader_device_combo.configure(values=labels)
        if labels:
            if self.reader_device_var.get() not in self._reader_devices_by_label:
                self.reader_device_var.set(labels[0])
        else:
            self.reader_device_var.set("")

    @staticmethod
    def _mapping_value(payload: object, *names: str):
        if not isinstance(payload, dict):
            return None
        expected = set(names)
        for key, value in payload.items():
            if isinstance(key, str) and key in expected:
                return value
            key_name = getattr(key, "name", None)
            if isinstance(key_name, str) and key_name in expected:
                return value
            key_str = str(key)
            if key_str in expected:
                return value
        return None

    @staticmethod
    def _to_hex(data: bytes | bytearray | memoryview | None) -> str:
        if data is None:
            return ""
        return bytes(data).hex()

    @staticmethod
    def _to_b64url(data: bytes | bytearray | memoryview | None) -> str:
        if data is None:
            return ""
        return urlsafe_b64encode(bytes(data)).decode("ascii").rstrip("=")

    @staticmethod
    def _fingerprint_for_device(device) -> str:
        _, fingerprint = OpenPicoKeysApp._format_device_label(device)
        return fingerprint

    def _read_key_snapshot(self, device_fingerprint: str, pin: str) -> dict:
        if device_fingerprint.startswith("pnp::"):
            raise ElevationRequiredError(
                "Key is detected via Windows PnP fallback, but direct CTAP HID access is blocked "
                "(Access denied on FIDO interface)."
            )

        from fido2.ctap import CtapError
        from fido2.ctap2 import Ctap2
        from fido2.ctap2.credman import CredentialManagement
        from fido2.ctap2.pin import ClientPin
        from fido2.hid import CtapHidDevice

        selected_device = None
        for device in CtapHidDevice.list_devices():
            _, fingerprint = self._format_device_label(device)
            if fingerprint == device_fingerprint:
                selected_device = device
                break
        if selected_device is None:
            raise BuildError("Selected key is not available. Refresh devices and try again.")

        selected_label, selected_fingerprint = self._format_device_label(selected_device)
        try:
            ctap2 = Ctap2(selected_device)
            info = ctap2.get_info()
        except Exception as exc:
            if self._is_access_denied_error(exc):
                raise ElevationRequiredError(
                    "Windows denied direct access to the Pico FIDO interface while reading key data."
                ) from exc
            raise
        snapshot: dict = {
            "device": {
                "label": selected_label,
                "fingerprint": selected_fingerprint,
            },
            "authenticator": {
                "aaguid_hex": self._to_hex(getattr(info, "aaguid", None)),
                "versions": list(getattr(info, "versions", []) or []),
                "extensions": list(getattr(info, "extensions", []) or []),
                "options": dict(getattr(info, "options", {}) or {}),
            },
            "credential_metadata": {},
            "resident_credentials": [],
        }

        client_pin = ClientPin(ctap2)
        try:
            retries = client_pin.get_pin_retries()
            snapshot["pin_retries_remaining"] = retries
        except Exception:
            snapshot["pin_retries_remaining"] = None

        permissions = None
        if hasattr(ClientPin, "PERMISSION"):
            permissions = getattr(ClientPin.PERMISSION, "CREDENTIAL_MGMT", None)

        try:
            if permissions is not None:
                pin_token = client_pin.get_pin_token(pin, permissions=permissions)
            else:
                pin_token = client_pin.get_pin_token(pin)
        except CtapError as exc:
            raise BuildError(f"PIN verification failed: {exc}") from exc

        credman = CredentialManagement(ctap2, client_pin.protocol, pin_token)

        try:
            metadata = credman.get_metadata()
            existing = self._mapping_value(metadata, "EXISTING_CRED_COUNT")
            remaining = self._mapping_value(metadata, "MAX_REMAINING_COUNT")
            snapshot["credential_metadata"] = {
                "existing_cred_count": existing,
                "max_remaining_count": remaining,
            }
        except Exception:
            snapshot["credential_metadata"] = {
                "existing_cred_count": None,
                "max_remaining_count": None,
                "available": False,
            }

        try:
            rps = list(credman.enumerate_rps())
        except Exception as exc:
            raise BuildError(
                "Credential enumeration failed. The key may not support resident credential management."
            ) from exc

        for rp_entry in rps:
            rp = self._mapping_value(rp_entry, "RP") or {}
            rp_id_hash = self._mapping_value(rp_entry, "RP_ID_HASH")
            rp_snapshot = {
                "rp": dict(rp) if isinstance(rp, dict) else {},
                "rp_id_hash_hex": self._to_hex(rp_id_hash),
                "credentials": [],
            }
            creds = list(credman.enumerate_creds(rp_id_hash))
            for cred_entry in creds:
                user = self._mapping_value(cred_entry, "USER") or {}
                cred_id = self._mapping_value(cred_entry, "CREDENTIAL_ID") or {}
                rp_snapshot["credentials"].append(
                    {
                        "user_name": user.get("name", "") if isinstance(user, dict) else "",
                        "user_display_name": user.get("displayName", "") if isinstance(user, dict) else "",
                        "user_id_b64url": self._to_b64url(user.get("id") if isinstance(user, dict) else None),
                        "credential_id_b64url": self._to_b64url(
                            cred_id.get("id") if isinstance(cred_id, dict) else None
                        ),
                        "credential_type": cred_id.get("type", "") if isinstance(cred_id, dict) else "",
                    }
                )
            snapshot["resident_credentials"].append(rp_snapshot)

        return snapshot

    @staticmethod
    def _is_access_denied_error(exc: BaseException) -> bool:
        text = str(exc).lower()
        return "access is denied" in text or "winerror 5" in text or "permission denied" in text

    def _snapshot_to_lines(self, snapshot: dict) -> list[str]:
        lines: list[str] = []
        device = snapshot.get("device", {}) if isinstance(snapshot, dict) else {}
        auth = snapshot.get("authenticator", {}) if isinstance(snapshot, dict) else {}
        metadata = snapshot.get("credential_metadata", {}) if isinstance(snapshot, dict) else {}
        resident = snapshot.get("resident_credentials", []) if isinstance(snapshot, dict) else []

        lines.append("FIDO2 Authenticator Info")
        lines.append("========================")
        lines.append(f"Device: {device.get('label', 'unknown')}")
        lines.append(f"AAGUID: {auth.get('aaguid_hex', '')}")
        lines.append(f"Versions: {', '.join(auth.get('versions', []) or [])}")
        lines.append(f"Extensions: {', '.join(auth.get('extensions', []) or [])}")
        lines.append(f"Options: {json.dumps(auth.get('options', {}) or {}, indent=2)}")
        retries = snapshot.get("pin_retries_remaining")
        lines.append(f"PIN retries remaining: {retries if retries is not None else 'unavailable'}")
        lines.append(
            "Resident credentials stored: "
            f"{metadata.get('existing_cred_count') if isinstance(metadata, dict) else 'unknown'}"
        )
        lines.append(
            "Resident credentials remaining: "
            f"{metadata.get('max_remaining_count') if isinstance(metadata, dict) else 'unknown'}"
        )
        lines.append("")

        if not resident:
            lines.append("No relying parties (resident credentials) found.")
            return lines

        lines.append("Resident Credentials")
        lines.append("====================")
        for rp_index, rp_entry in enumerate(resident, start=1):
            rp = rp_entry.get("rp", {}) if isinstance(rp_entry, dict) else {}
            rp_name = rp.get("name", "") if isinstance(rp, dict) else ""
            rp_id = rp.get("id", "") if isinstance(rp, dict) else ""
            lines.append(f"{rp_index}. RP: {rp_name or '(no name)'}")
            lines.append(f"   ID: {rp_id or '(no id)'}")
            lines.append(f"   RP ID Hash: {rp_entry.get('rp_id_hash_hex', '')}")
            credentials = rp_entry.get("credentials", []) if isinstance(rp_entry, dict) else []
            if not credentials:
                lines.append("   Credentials: none")
                continue
            for cred_index, cred in enumerate(credentials, start=1):
                lines.append(f"   Credential {cred_index}:")
                lines.append(f"     User: {cred.get('user_name', '') or '(no name)'}")
                lines.append(f"     Display: {cred.get('user_display_name', '') or '(no display)'}")
                lines.append(f"     User ID (b64url): {cred.get('user_id_b64url', '')}")
                lines.append(f"     Credential ID (b64url): {cred.get('credential_id_b64url', '')}")
            lines.append("")
        return lines

    @staticmethod
    def _encrypt_backup_payload(payload: dict, password: str) -> str:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

        plaintext = json.dumps(payload, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
        salt = os.urandom(16)
        nonce = os.urandom(12)
        n = 2**14
        r = 8
        p = 1
        kdf = Scrypt(salt=salt, length=32, n=n, r=r, p=p)
        key = kdf.derive(password.encode("utf-8"))
        aad = b"openpicokeys-backup-v1"
        ciphertext = AESGCM(key).encrypt(nonce, plaintext, aad)
        envelope = {
            "format": "openpicokeys-encrypted-backup-v1",
            "kdf": {
                "name": "scrypt",
                "n": n,
                "r": r,
                "p": p,
                "salt_b64": b64encode(salt).decode("ascii"),
            },
            "cipher": "aes-256-gcm",
            "nonce_b64": b64encode(nonce).decode("ascii"),
            "aad": "openpicokeys-backup-v1",
            "ciphertext_b64": b64encode(ciphertext).decode("ascii"),
        }
        return json.dumps(envelope, indent=2)

    @staticmethod
    def _decrypt_backup_payload(encrypted_json_text: str, password: str) -> dict:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

        envelope = json.loads(encrypted_json_text)
        if not isinstance(envelope, dict):
            raise BuildError("Invalid backup format.")
        if envelope.get("format") != "openpicokeys-encrypted-backup-v1":
            raise BuildError("Unsupported backup format.")
        kdf_meta = envelope.get("kdf", {})
        if not isinstance(kdf_meta, dict) or kdf_meta.get("name") != "scrypt":
            raise BuildError("Unsupported KDF in backup file.")
        salt = b64decode(kdf_meta.get("salt_b64", ""))
        nonce = b64decode(envelope.get("nonce_b64", ""))
        ciphertext = b64decode(envelope.get("ciphertext_b64", ""))
        aad = str(envelope.get("aad", "")).encode("utf-8")
        kdf = Scrypt(
            salt=salt,
            length=32,
            n=int(kdf_meta.get("n", 2**14)),
            r=int(kdf_meta.get("r", 8)),
            p=int(kdf_meta.get("p", 1)),
        )
        key = kdf.derive(password.encode("utf-8"))
        try:
            plaintext = AESGCM(key).decrypt(nonce, ciphertext, aad)
        except Exception as exc:
            raise BuildError("Failed to decrypt backup. Wrong password or corrupted file.") from exc
        payload = json.loads(plaintext.decode("utf-8"))
        if not isinstance(payload, dict):
            raise BuildError("Backup payload is invalid.")
        return payload

    def _target_device_fingerprints_for_scope(self, scope: str) -> list[str]:
        if scope == "All-Keys":
            devices = self._list_key_reader_devices()
            if not devices:
                raise BuildError("No security keys detected.")
            return [fingerprint for _, fingerprint in devices]

        selected_label = self.reader_device_var.get().strip()
        if not selected_label:
            raise BuildError("Select a security key first.")
        selected_fingerprint = self._reader_devices_by_label.get(selected_label)
        if not selected_fingerprint:
            devices = self._list_key_reader_devices()
            self._post("reader_devices", devices)
            selected_fingerprint = self._reader_devices_by_label.get(selected_label)
        if not selected_fingerprint:
            raise BuildError("Selected key is no longer available. Refresh devices.")
        return [selected_fingerprint]

    def _on_refresh_key_devices(self) -> None:
        self._refresh_key_devices(silent_if_missing=False)

    def _refresh_key_devices(self, silent_if_missing: bool) -> None:
        if not self._ensure_key_reader_dependencies(prompt_if_missing=not silent_if_missing):
            return

        def worker() -> None:
            self._post("status", "Refreshing key devices...")
            devices = self._list_key_reader_devices()
            self._post("reader_devices", devices)
            count = len(devices)
            self._post("reader_log", f"Detected {count} security key(s).")
            pnp_count = sum(1 for _, fp in devices if fp.startswith("pnp::"))
            if pnp_count:
                self._post(
                    "reader_log",
                    f"{pnp_count} device(s) are in Pico FIDO PnP fallback mode (detected, but CTAP open may be blocked).",
                )
            if count == 0:
                self._post(
                    "reader_log",
                    "No FIDO HID keys found. Replug the key and make sure the firmware exposes FIDO2 USB HID.",
                )
            self._post("success", f"Detected {count} key(s)")

        self._start_background(worker)

    def _on_tab_changed(self, _event=None) -> None:
        if self._busy or self._notebook is None:
            return
        current = self._notebook.tab(self._notebook.select(), "text")
        if current == "Key Reader":
            self._refresh_key_devices(silent_if_missing=True)

    def _on_read_key_data(self) -> None:
        if not self._ensure_key_reader_dependencies(prompt_if_missing=True):
            return

        selected_label = self.reader_device_var.get().strip()
        if not selected_label:
            messagebox.showerror("OpenPicoKeys", "Select a security key first.")
            return
        device_fingerprint = self._reader_devices_by_label.get(selected_label)
        if not device_fingerprint:
            messagebox.showerror("OpenPicoKeys", "Selected key is no longer available. Refresh devices.")
            return
        pin = self.reader_pin_var.get().strip()
        if not pin:
            messagebox.showerror("OpenPicoKeys", "PIN is required to read key content.")
            return

        self.key_reader_output.configure(state="normal")
        self.key_reader_output.delete("1.0", tk.END)
        self.key_reader_output.configure(state="disabled")

        def worker() -> None:
            self._post("status", "Reading key content...")
            snapshot = self._read_key_snapshot(device_fingerprint, pin)
            lines = self._snapshot_to_lines(snapshot)
            for line in lines:
                self._post("reader_log", line)
            self._post("success", "Key content read complete")

        self._start_background(worker)

    def _on_backup_keys(self) -> None:
        if not self._ensure_key_reader_dependencies(prompt_if_missing=True):
            return
        if not self._ensure_python_module(
            module_name="cryptography",
            package_name="cryptography",
            display_name="cryptography",
            reason="encrypt key backups",
        ):
            return

        pin = self.reader_pin_var.get().strip()
        if not pin:
            messagebox.showerror("OpenPicoKeys", "PIN is required for backup.")
            return

        password = simpledialog.askstring("Backup Password", "Enter backup password:", show="*")
        if not password:
            return
        confirm = simpledialog.askstring("Backup Password", "Confirm backup password:", show="*")
        if password != confirm:
            messagebox.showerror("OpenPicoKeys", "Passwords do not match.")
            return

        target_path = filedialog.asksaveasfilename(
            title="Save encrypted backup file",
            defaultextension=".opkbackup",
            filetypes=[("OpenPicoKeys backup", "*.opkbackup"), ("JSON files", "*.json"), ("All files", "*.*")],
        )
        if not target_path:
            return

        scope = self.reader_scope_var.get().strip() or "Currently Selected Key"

        def worker() -> None:
            self._post("status", "Creating key backup...")
            fingerprints = self._target_device_fingerprints_for_scope(scope)
            snapshots = [self._read_key_snapshot(fp, pin) for fp in fingerprints]
            payload = {
                "format": "openpicokeys-key-backup-v1",
                "created_at_utc": datetime.now(timezone.utc).isoformat(),
                "scope": scope,
                "device_count": len(snapshots),
                "devices": snapshots,
            }
            encrypted = self._encrypt_backup_payload(payload, password)
            out = Path(target_path).expanduser().resolve()
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_text(encrypted, encoding="utf-8")
            self._post("reader_log", f"Backup written: {out}")
            self._post("success", "Backup created")

        self._start_background(worker)

    def _on_load_keys(self) -> None:
        if not self._ensure_key_reader_dependencies(prompt_if_missing=True):
            return
        if not self._ensure_python_module(
            module_name="cryptography",
            package_name="cryptography",
            display_name="cryptography",
            reason="decrypt key backups",
        ):
            return

        source_path = filedialog.askopenfilename(
            title="Select encrypted backup file",
            filetypes=[("OpenPicoKeys backup", "*.opkbackup"), ("JSON files", "*.json"), ("All files", "*.*")],
        )
        if not source_path:
            return
        password = simpledialog.askstring("Backup Password", "Enter backup password:", show="*")
        if not password:
            return
        pin = self.reader_pin_var.get().strip()
        if not pin:
            messagebox.showerror("OpenPicoKeys", "PIN is required for key loading.")
            return

        scope = self.reader_scope_var.get().strip() or "Currently Selected Key"
        source = Path(source_path).expanduser().resolve()

        def worker() -> None:
            self._post("status", "Loading key backup...")
            encrypted_json = source.read_text(encoding="utf-8")
            payload = self._decrypt_backup_payload(encrypted_json, password)
            if payload.get("format") != "openpicokeys-key-backup-v1":
                raise BuildError("Unsupported decrypted backup payload format.")

            fingerprints = self._target_device_fingerprints_for_scope(scope)
            # Validate selected targets are accessible with the provided PIN.
            for fingerprint in fingerprints:
                snapshot = self._read_key_snapshot(fingerprint, pin)
                device_label = snapshot.get("device", {}).get("label", "unknown")
                self._post("reader_log", f"PIN check OK for: {device_label}")

            backed_up_devices = payload.get("devices", [])
            backed_up_count = len(backed_up_devices) if isinstance(backed_up_devices, list) else 0
            self._post("reader_log", f"Backup contains {backed_up_count} device snapshot(s).")
            self._post(
                "reader_log",
                "Device-side credential import is not available through standard CTAP2 APIs. "
                "The backup was decrypted and validated, but full key restore requires vendor-specific support.",
            )
            self._post("success", "Load completed (validation mode)")

        self._start_background(worker)

    def _ensure_key_reader_dependencies(self, prompt_if_missing: bool) -> bool:
        if not self._ensure_python_module(
            module_name="fido2",
            package_name="fido2",
            display_name="python-fido2",
            reason="read key content",
            prompt_if_missing=prompt_if_missing,
        ):
            return False
        if sys.platform.startswith("win") and not self._ensure_python_module(
            module_name="hid",
            package_name="hidapi",
            display_name="hidapi",
            reason="access FIDO HID devices on Windows",
            prompt_if_missing=prompt_if_missing,
        ):
            return False
        return True

    def _save_profile(self) -> None:
        try:
            profile = self._collect_profile()
        except BuildError as exc:
            messagebox.showerror("OpenPicoKeys", str(exc))
            return

        target = filedialog.asksaveasfilename(
            title="Save OpenPicoKeys profile",
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")],
        )
        if not target:
            return

        path = Path(target)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(profile.to_dict(), indent=2), encoding="utf-8")
        self.status_var.set(f"Profile saved: {path}")

    def _load_profile(self) -> None:
        source = filedialog.askopenfilename(
            title="Load OpenPicoKeys profile",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")],
        )
        if not source:
            return

        payload = json.loads(Path(source).read_text(encoding="utf-8"))
        profile = BuildProfile.from_dict(payload)
        self.source_var.set(profile.source_dir)
        self.sdk_var.set(profile.pico_sdk_path)
        self.output_var.set(profile.output_uf2)
        self.board_var.set(profile.board)
        self.key_name_var.set(profile.key_name)
        self.manufacturer_var.set(profile.manufacturer)
        self.website_var.set(profile.website)
        self.usb_vid_var.set(profile.usb_vid)
        self.usb_pid_var.set(profile.usb_pid)
        self.disable_led_var.set(profile.disable_led)
        self.status_var.set(f"Profile loaded: {source}")

    def _on_prepare_source(self) -> None:
        try:
            profile = self._collect_profile()
        except BuildError as exc:
            messagebox.showerror("OpenPicoKeys", str(exc))
            return
        source = Path(profile.source_dir).expanduser().resolve()

        def worker() -> None:
            builder = FirmwareBuilder(log_callback=lambda line: self._post("log", line))
            self._post("status", "Preparing source...")
            builder.prepare_source(source, clone_if_missing=True)
            self._post("log", f"Source ready at: {source}")
            self._post("success", "Source prepared")

        self._start_background(worker)

    def _on_build(self) -> None:
        try:
            profile = self._collect_profile()
        except BuildError as exc:
            messagebox.showerror("OpenPicoKeys", str(exc))
            return

        def worker() -> None:
            builder = FirmwareBuilder(log_callback=lambda line: self._post("log", line))
            self._post("status", "Building firmware...")
            result = builder.build(profile)
            self._post("log", f"Build directory: {result.build_dir}")
            self._post("success", f"UF2 created: {result.output_uf2}")
            self._post("info", f"Firmware generated:\n{result.output_uf2}")

        self._start_background(worker)


def run() -> None:
    app = OpenPicoKeysApp()
    app.mainloop()
