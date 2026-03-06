from __future__ import annotations

import json
import os
import platform
import queue
import re
import secrets
import shutil
import sys
import tempfile
import threading
import time
import traceback
import tkinter as tk
from datetime import datetime
from pathlib import Path
from tkinter import filedialog, messagebox, scrolledtext, ttk

from .builder import BuildError, FirmwareBuilder
from .customizer import FirmwareCustomizer, CustomizerError
from .key_manager import KeyManagerError, KeyManagerService
from .models import BuildProfile
from .privilege import admin_required_message, is_admin


class OpenPicoKeysApp(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title("OpenPicoKeys")
        self._apply_app_icon()
        self.geometry("980x760")
        self.minsize(900, 700)

        self._events: queue.Queue[tuple[str, object]] = queue.Queue()
        self._worker: threading.Thread | None = None
        self._busy = False
        self._bootsel_prompt_event: threading.Event | None = None
        self._bootsel_prompt_result = False

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
        self.status_var = tk.StringVar(value="Ready")

        self._notebook: ttk.Notebook | None = None

        # Track the profile used for the last successful build / customizer apply
        self._last_built_profile: dict | None = None
        self._last_cust_build_profile: dict | None = None
        self._last_cust_applied: dict | None = None

        # Customizer state
        self._cust_service = FirmwareCustomizer(
            log_callback=lambda line: self._post("cust_log", line),
        )

        self.cust_input_var = tk.StringVar(value="")
        self.cust_output_var = tk.StringVar(value="")
        self.cust_key_name_var = tk.StringVar(value="")
        self.cust_manufacturer_var = tk.StringVar(value="")
        self.cust_website_var = tk.StringVar(value="")
        self.cust_vid_var = tk.StringVar(value="")
        self.cust_pid_var = tk.StringVar(value="")
        self.cust_board_var = tk.StringVar(value="(scan firmware to detect)")
        self.cust_disable_led_var = tk.BooleanVar(value=False)
        self.cust_status_var = tk.StringVar(value="Ready for backup, install, and restore.")

        # Backup Manager state
        self._is_admin = is_admin()
        self._km_service = KeyManagerService(
            log_callback=lambda line: self._post("km_log", line),
        )
        self.km_password_var = tk.StringVar(value="")
        self.km_status_var = tk.StringVar(
            value=(
                "Ready."
                if self._is_admin
                else admin_required_message("Backup Manager")
            )
        )
        self.km_capabilities_var = tk.StringVar(value="Not probed")
        self._key_manager_widgets: list[ttk.Widget] = []

        self._interactive_widgets: list[ttk.Widget] = []
        self._cache_dir = Path.cwd() / ".picokeys" / "builds"
        self._cache_dir.mkdir(parents=True, exist_ok=True)
        self._autoload_default_customizer_profile()
        self._build_ui()
        self.after(100, self._drain_events)
        self.after(300, self._check_dependencies_on_startup)

    @staticmethod
    def _default_profile_path() -> Path:
        return Path.cwd() / "profiles" / "default-profile.json"

    @staticmethod
    def _icon_ico_path() -> Path:
        return Path.cwd() / "icon.ico"

    def _apply_app_icon(self) -> None:
        """Apply window/app icon from pre-converted icon.ico."""
        ico_path = self._icon_ico_path()
        if ico_path.is_file():
            try:
                self.iconbitmap(default=str(ico_path))
            except tk.TclError:
                pass

    def _autoload_default_customizer_profile(self) -> None:
        """Load profiles/default-profile.json into customizer placeholders when available."""
        default_profile = self._default_profile_path()
        if not default_profile.is_file():
            return
        try:
            payload = json.loads(default_profile.read_text(encoding="utf-8"))
            profile = BuildProfile.from_dict(payload)
        except (json.JSONDecodeError, OSError, TypeError, ValueError):
            # Keep built-in defaults if preset is missing or invalid.
            return

        self._apply_profile_to_customizer_fields(profile)

    def _apply_profile_to_customizer_fields(self, profile: BuildProfile) -> None:
        """Apply a BuildProfile to Key Customizer form fields."""
        self.cust_key_name_var.set(profile.key_name)
        self.cust_manufacturer_var.set(profile.manufacturer)
        self.cust_website_var.set(profile.website)
        self.cust_vid_var.set(profile.usb_vid)
        self.cust_pid_var.set(profile.usb_pid)
        self.cust_board_var.set(profile.board)
        self.cust_disable_led_var.set(profile.disable_led)
        if not self.cust_output_var.get().strip():
            self.cust_output_var.set(profile.output_uf2)

    def _build_ui(self) -> None:
        root = ttk.Frame(self, padding=12)
        root.grid(sticky="nsew")
        self.columnconfigure(0, weight=1)
        self.rowconfigure(0, weight=1)
        root.columnconfigure(0, weight=1)
        root.rowconfigure(1, weight=1)

        header = ttk.Label(
            root,
            text="OpenPicoKeys - Open source PicoKey customizer & manager",
            font=("Segoe UI", 13, "bold"),
        )
        header.grid(row=0, column=0, sticky="w")

        notebook = ttk.Notebook(root)
        notebook.grid(row=1, column=0, sticky="nsew", pady=(10, 0))
        self._notebook = notebook

        firmware_tab = ttk.Frame(notebook)
        customizer_tab = ttk.Frame(notebook)
        key_manager_tab = ttk.Frame(notebook)
        notebook.add(firmware_tab, text="Firmware Builder")
        notebook.add(customizer_tab, text="Firmware Customizer")
        notebook.add(key_manager_tab, text="Backup Manager")

        firmware_tab.columnconfigure(0, weight=1)
        firmware_tab.rowconfigure(0, weight=1)
        builder_root = ttk.Frame(firmware_tab, padding=8)
        builder_root.grid(row=0, column=0, sticky="nsew")
        builder_root.columnconfigure(0, weight=1)
        builder_root.rowconfigure(3, weight=1)

        subtitle = ttk.Label(
            builder_root,
            text="Step 1: Select installation folder  |  Step 2: Customize firmware  |  Step 3: Build .uf2",
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
            text="Disable LED",
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

        logs_frame = ttk.LabelFrame(builder_root, text="Build Logs")
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
        quick_install_btn = ttk.Button(
            status_frame, text="\u26a1 Quick Install", command=self._on_quick_install_builder
        )
        quick_install_btn.grid(row=0, column=1, sticky="e", padx=(6, 0))
        firmware_help_btn = ttk.Button(
            status_frame, text="How to install firmware", command=self._show_install_help
        )
        firmware_help_btn.grid(row=0, column=2, sticky="e", padx=(6, 0))

        # ---- Firmware Customizer tab ----
        customizer_tab.columnconfigure(0, weight=1)
        customizer_tab.rowconfigure(0, weight=1)

        cust_root = ttk.Frame(customizer_tab, padding=8)
        cust_root.grid(row=0, column=0, sticky="nsew")
        cust_root.columnconfigure(0, weight=1)
        cust_root.rowconfigure(4, weight=1)

        cust_subtitle = ttk.Label(
            cust_root,
            text=(
                "Step 1: Configure custom values  |  Step 2: Build new firmware  |  "
                "Step 3: Install with backup restore (no patching)"
            ),
        )
        cust_subtitle.grid(row=0, column=0, sticky="w", pady=(2, 12))

        cust_input_frame = ttk.LabelFrame(cust_root, text="Step 1 - Input Firmware")
        cust_input_frame.grid(row=1, column=0, sticky="ew")
        for col in range(4):
            cust_input_frame.columnconfigure(col, weight=1 if col == 1 else 0)

        ttk.Label(cust_input_frame, text="Input UF2 (optional)").grid(row=0, column=0, padx=6, pady=6, sticky="w")
        cust_input_entry = ttk.Entry(cust_input_frame, textvariable=self.cust_input_var)
        cust_input_entry.grid(row=0, column=1, padx=6, pady=6, sticky="ew")
        cust_input_browse = ttk.Button(cust_input_frame, text="Browse", command=self._on_cust_browse_input)
        cust_input_browse.grid(row=0, column=2, padx=6, pady=6, sticky="ew")
        cust_cache_browse = ttk.Button(cust_input_frame, text="From Cache", command=self._on_cust_browse_cache)
        cust_cache_browse.grid(row=0, column=3, padx=6, pady=6, sticky="ew")

        ttk.Label(cust_input_frame, text="Backup").grid(row=1, column=0, padx=6, pady=6, sticky="w")
        cust_backup_note = ttk.Label(
            cust_input_frame,
            text="Automatic: one-time random password + temporary encrypted backup",
        )
        cust_backup_note.grid(row=1, column=1, padx=6, pady=6, sticky="w")
        cust_scan_button = ttk.Button(cust_input_frame, text="Scan UF2 (optional)", command=self._on_cust_scan)
        cust_scan_button.grid(row=1, column=2, padx=6, pady=6, sticky="ew")

        cust_profile_frame = ttk.LabelFrame(cust_root, text="Step 2 - Device Customization")
        cust_profile_frame.grid(row=2, column=0, sticky="ew", pady=(12, 0))
        for col in range(4):
            cust_profile_frame.columnconfigure(col, weight=1)

        ttk.Label(cust_profile_frame, text="Key Name (USB product)").grid(
            row=0, column=0, padx=6, pady=6, sticky="w"
        )
        cust_key_name_entry = ttk.Entry(cust_profile_frame, textvariable=self.cust_key_name_var)
        cust_key_name_entry.grid(row=0, column=1, padx=6, pady=6, sticky="ew")

        ttk.Label(cust_profile_frame, text="Manufacturer").grid(row=0, column=2, padx=6, pady=6, sticky="w")
        cust_manufacturer_entry = ttk.Entry(cust_profile_frame, textvariable=self.cust_manufacturer_var)
        cust_manufacturer_entry.grid(row=0, column=3, padx=6, pady=6, sticky="ew")

        ttk.Label(cust_profile_frame, text="Website (WebUSB)").grid(row=1, column=0, padx=6, pady=6, sticky="w")
        cust_website_entry = ttk.Entry(cust_profile_frame, textvariable=self.cust_website_var)
        cust_website_entry.grid(row=1, column=1, padx=6, pady=6, sticky="ew")

        ttk.Label(cust_profile_frame, text="Board").grid(row=1, column=2, padx=6, pady=6, sticky="w")
        cust_board_entry = ttk.Entry(cust_profile_frame, textvariable=self.cust_board_var, state="readonly")
        cust_board_entry.grid(row=1, column=3, padx=6, pady=6, sticky="ew")

        ttk.Label(cust_profile_frame, text="USB VID").grid(row=2, column=0, padx=6, pady=6, sticky="w")
        cust_vid_entry = ttk.Entry(cust_profile_frame, textvariable=self.cust_vid_var)
        cust_vid_entry.grid(row=2, column=1, padx=6, pady=6, sticky="ew")

        ttk.Label(cust_profile_frame, text="USB PID").grid(row=2, column=2, padx=6, pady=6, sticky="w")
        cust_pid_entry = ttk.Entry(cust_profile_frame, textvariable=self.cust_pid_var)
        cust_pid_entry.grid(row=2, column=3, padx=6, pady=6, sticky="ew")

        cust_disable_led_check = ttk.Checkbutton(
            cust_profile_frame,
            text="Disable LED",
            variable=self.cust_disable_led_var,
        )
        cust_disable_led_check.grid(row=3, column=0, columnspan=2, padx=6, pady=6, sticky="w")

        ttk.Label(cust_profile_frame, text="Output UF2").grid(row=4, column=0, padx=6, pady=6, sticky="w")
        cust_output_entry = ttk.Entry(cust_profile_frame, textvariable=self.cust_output_var)
        cust_output_entry.grid(row=4, column=1, padx=6, pady=6, sticky="ew")
        cust_output_browse = ttk.Button(cust_profile_frame, text="Browse", command=self._on_cust_browse_output)
        cust_output_browse.grid(row=4, column=2, padx=6, pady=6, sticky="ew")

        cust_action_frame = ttk.Frame(cust_profile_frame)
        cust_action_frame.grid(row=4, column=3, padx=6, pady=6, sticky="e")
        cust_save_button = ttk.Button(cust_action_frame, text="Save Profile", command=self._save_cust_profile)
        cust_save_button.grid(row=0, column=0, padx=(0, 6))
        cust_load_button = ttk.Button(cust_action_frame, text="Load Profile", command=self._on_cust_load_profile)
        cust_load_button.grid(row=0, column=1, padx=(0, 6))

        cust_logs_frame = ttk.LabelFrame(cust_root, text="Customizer Logs")
        cust_logs_frame.grid(row=4, column=0, sticky="nsew", pady=(12, 0))
        cust_logs_frame.columnconfigure(0, weight=1)
        cust_logs_frame.rowconfigure(0, weight=1)

        self.cust_logs = scrolledtext.ScrolledText(cust_logs_frame, wrap=tk.WORD, height=20)
        self.cust_logs.grid(row=0, column=0, sticky="nsew")
        self.cust_logs.configure(state="disabled")

        cust_status_frame = ttk.Frame(cust_root)
        cust_status_frame.grid(row=5, column=0, sticky="ew", pady=(8, 0))
        cust_status_frame.columnconfigure(0, weight=1)
        cust_status_label = ttk.Label(cust_status_frame, textvariable=self.cust_status_var)
        cust_status_label.grid(row=0, column=0, sticky="w")
        cust_quick_install_btn = ttk.Button(
            cust_status_frame,
            text="Apply",
            command=self._on_quick_install_cust,
        )
        cust_quick_install_btn.grid(row=0, column=1, sticky="e", padx=(6, 0))

        # ---- Backup Manager tab ----
        key_manager_tab.columnconfigure(0, weight=1)
        key_manager_tab.rowconfigure(0, weight=1)

        km_root = ttk.Frame(key_manager_tab, padding=8)
        km_root.grid(row=0, column=0, sticky="nsew")
        km_root.columnconfigure(0, weight=1)
        km_root.rowconfigure(3, weight=1)

        km_subtitle = ttk.Label(
            km_root,
            text="FIDO-style encrypted backup/restore (capability-gated by firmware)",
        )
        km_subtitle.grid(row=0, column=0, sticky="w", pady=(2, 12))

        km_op_frame = ttk.LabelFrame(km_root, text="Operations")
        km_op_frame.grid(row=1, column=0, sticky="ew")
        for col in range(4):
            km_op_frame.columnconfigure(col, weight=1)

        ttk.Label(km_op_frame, text="Encryption password").grid(row=0, column=0, padx=6, pady=6, sticky="w")
        km_password_entry = ttk.Entry(km_op_frame, textvariable=self.km_password_var, show="*")
        km_password_entry.grid(row=0, column=1, padx=6, pady=6, sticky="ew")

        km_probe_btn = ttk.Button(km_op_frame, text="Probe Device", command=self._on_km_probe)
        km_probe_btn.grid(row=0, column=2, padx=6, pady=6, sticky="ew")
        km_preview_btn = ttk.Button(km_op_frame, text="Preview Backup", command=self._on_km_preview)
        km_preview_btn.grid(row=0, column=3, padx=6, pady=6, sticky="ew")

        km_backup_btn = ttk.Button(km_op_frame, text="Backup to Encrypted File", command=self._on_km_backup)
        km_backup_btn.grid(row=1, column=0, columnspan=2, padx=6, pady=6, sticky="ew")
        km_restore_btn = ttk.Button(km_op_frame, text="Restore Encrypted Backup", command=self._on_km_restore)
        km_restore_btn.grid(row=1, column=2, columnspan=2, padx=6, pady=6, sticky="ew")

        km_caps_frame = ttk.LabelFrame(km_root, text="Detected Capabilities")
        km_caps_frame.grid(row=2, column=0, sticky="ew", pady=(12, 0))
        km_caps_frame.columnconfigure(0, weight=1)
        km_caps_label = ttk.Label(
            km_caps_frame,
            textvariable=self.km_capabilities_var,
            justify="left",
        )
        km_caps_label.grid(row=0, column=0, padx=8, pady=8, sticky="w")

        km_logs_frame = ttk.LabelFrame(km_root, text="Backup Manager Log")
        km_logs_frame.grid(row=3, column=0, sticky="nsew", pady=(12, 0))
        km_logs_frame.columnconfigure(0, weight=1)
        km_logs_frame.rowconfigure(0, weight=1)

        self.km_logs = scrolledtext.ScrolledText(km_logs_frame, wrap=tk.WORD, height=20)
        self.km_logs.grid(row=0, column=0, sticky="nsew")
        self.km_logs.configure(state="disabled")

        km_status_frame = ttk.Frame(km_root)
        km_status_frame.grid(row=4, column=0, sticky="ew", pady=(8, 0))
        km_status_frame.columnconfigure(0, weight=1)
        km_status_label = ttk.Label(km_status_frame, textvariable=self.km_status_var)
        km_status_label.grid(row=0, column=0, sticky="w")

        self._key_manager_widgets = [
            km_password_entry,
            km_probe_btn,
            km_preview_btn,
            km_backup_btn,
            km_restore_btn,
        ]

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
            quick_install_btn,
            cust_input_entry,
            cust_input_browse,
            cust_cache_browse,
            cust_scan_button,
            cust_key_name_entry,
            cust_manufacturer_entry,
            cust_website_entry,
            cust_vid_entry,
            cust_pid_entry,
            cust_disable_led_check,
            cust_output_entry,
            cust_output_browse,
            cust_save_button,
            cust_load_button,
            cust_quick_install_btn,
            km_password_entry,
            km_probe_btn,
            km_preview_btn,
            km_backup_btn,
            km_restore_btn,
        ]
        self._apply_key_manager_admin_gate()

    def _append_to_log(self, widget: scrolledtext.ScrolledText, message: str) -> None:
        """Append *message* to a ScrolledText log widget."""
        view_before = widget.yview()
        at_bottom = view_before[1] >= 0.999
        widget.configure(state="normal")
        widget.insert(tk.END, message.rstrip() + "\n")
        if at_bottom:
            widget.see(tk.END)
        else:
            widget.yview_moveto(view_before[0])
        widget.configure(state="disabled")

    def _append_log(self, message: str) -> None:
        self._append_to_log(self.logs, message)

    def _append_cust_log(self, message: str) -> None:
        if hasattr(self, "cust_logs"):
            self._append_to_log(self.cust_logs, message)

    def _append_km_log(self, message: str) -> None:
        self._append_to_log(self.km_logs, message)

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
            elif kind == "cust_scanned":
                self._handle_cust_scanned(payload)
            elif kind == "cust_status":
                self.cust_status_var.set(str(payload))
                self._append_cust_log(str(payload))
            elif kind == "cust_log":
                self._append_cust_log(str(payload))
            elif kind == "cust_bootsel_prompt":
                proceed = messagebox.askokcancel(
                    "Enable BOOTSEL mode",
                    "Backup is complete.\n\n"
                    "Now put your Pico in BOOTSEL mode:\n"
                    "1. Unplug the Pico\n"
                    "2. Hold BOOTSEL\n"
                    "3. Plug it back in while holding BOOTSEL\n"
                    "4. Release BOOTSEL once RPI-RP2 appears\n\n"
                    "Press OK to continue installation, or Cancel to abort.",
                )
                self._bootsel_prompt_result = proceed
                if self._bootsel_prompt_event is not None:
                    self._bootsel_prompt_event.set()
            elif kind == "km_status":
                self.km_status_var.set(str(payload))
            elif kind == "km_log":
                self._append_km_log(str(payload))
            elif kind == "km_caps":
                self._handle_km_caps(payload)

        self.after(100, self._drain_events)

    def _set_busy(self, busy: bool) -> None:
        self._busy = busy
        for widget in self._interactive_widgets:
            if busy:
                widget.state(["disabled"])
            else:
                widget.state(["!disabled"])
            if isinstance(widget, ttk.Combobox) and not busy:
                widget.configure(state="readonly")
        if busy:
            self.status_var.set("Working...")
        elif self.status_var.get() == "Working...":
            self.status_var.set("Ready")
        if not busy:
            self._apply_key_manager_admin_gate()

    def _start_background(self, worker) -> None:
        if self._worker is not None and self._worker.is_alive():
            messagebox.showwarning("OpenPicoKeys", "A task is already running.")
            return

        def runner() -> None:
            try:
                worker()
            except (BuildError, CustomizerError, KeyManagerError) as exc:
                self._post("error", str(exc))
            except Exception as exc:  # pragma: no cover
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
        path.write_text(json.dumps(profile.to_dict(), indent=2, ensure_ascii=False), encoding="utf-8")
        self.status_var.set(f"Profile saved: {path}")

    def _load_profile(self) -> None:
        source = filedialog.askopenfilename(
            title="Load OpenPicoKeys profile",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")],
        )
        if not source:
            return

        try:
            payload = json.loads(Path(source).read_text(encoding="utf-8"))
            profile = BuildProfile.from_dict(payload)
        except (json.JSONDecodeError, OSError, TypeError, ValueError) as exc:
            messagebox.showerror("OpenPicoKeys", f"Failed to load profile:\n{exc}")
            return

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

    def _cache_uf2(self, source: Path, prefix: str, log_fn) -> Path:
        """Copy *source* into the cache directory with a timestamped name."""
        stamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        safe_prefix = re.sub(r"[^\w\-]", "_", prefix.strip() or "firmware")
        cached = self._cache_dir / f"{safe_prefix}-{stamp}.uf2"
        shutil.copy2(source, cached)
        log_fn(f"Cached: {cached.name}")
        return cached

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
            self._last_built_profile = profile.to_dict()
            self._cache_uf2(result.output_uf2, profile.key_name or "firmware",
                            lambda line: self._post("log", line))
            self._post("log", f"Build directory: {result.build_dir}")
            self._post("success", f"UF2 created: {result.output_uf2}")
            self._post("info", f"Firmware generated:\n{result.output_uf2}")

        self._start_background(worker)

    # ------------------------------------------------------------------ #
    #  Key Customizer helpers                                              #
    # ------------------------------------------------------------------ #

    _INSTALL_HELP_TEXT = (
        "How to install firmware on a Raspberry Pi Pico\n"
        "================================================\n"
        "\n"
        "1. Locate the .uf2 file\n"
        "   After building or customizing, you will have a .uf2 firmware file.\n"
        "\n"
        "2. Enter BOOTSEL mode\n"
        "   - Unplug the Pico from your computer.\n"
        "   - Press and hold the BOOTSEL button on the board.\n"
        "   - While still holding the button, plug the Pico back in via USB.\n"
        "   - Release the button once connected.\n"
        "   The Pico will appear as a USB mass-storage drive (named RPI-RP2).\n"
        "\n"
        "3. Copy the firmware\n"
        "   - Drag and drop the .uf2 file onto the RPI-RP2 drive.\n"
        "   - Alternatively, copy it via the command line:\n"
        "       Windows:  copy firmware.uf2 E:\\\n"
        "       Linux:    cp firmware.uf2 /media/$USER/RPI-RP2/\n"
        "       macOS:    cp firmware.uf2 /Volumes/RPI-RP2/\n"
        "\n"
        "4. Wait for the reboot\n"
        "   The Pico will automatically unmount, flash the firmware, and reboot.\n"
        "   This usually takes only a few seconds.\n"
        "\n"
        "5. Verify\n"
        "   Once the Pico reboots it will enumerate as a FIDO2 security key.\n"
        "   You can check Device Manager (Windows), lsusb (Linux) or\n"
        "   System Information (macOS) to confirm the new USB product name,\n"
        "   VID/PID and other descriptor values.\n"
        "\n"
        "Tips\n"
        "----\n"
        "- If the RPI-RP2 drive does not appear, try a different USB cable\n"
        "  (some cables are charge-only and lack data lines).\n"
        "- On Pico 2 (RP2350) the process is identical; the drive still\n"
        "  appears as RPI-RP2.\n"
        "- Flashing a new .uf2 replaces the running firmware but does NOT\n"
        "  erase FIDO credential data stored in flash, provided the new\n"
        "  firmware uses the same data layout (e.g. an optimized build\n"
        "  from the Key Customizer tab).\n"
        "- To fully erase the Pico, flash the official 'flash_nuke.uf2'\n"
        "  from Raspberry Pi before loading new firmware.\n"
    )

    def _show_install_help(self) -> None:
        """Open a read-only text window with firmware installation instructions."""
        win = tk.Toplevel(self)
        win.title("How to install firmware")
        win.geometry("640x520")
        win.minsize(480, 360)
        win.columnconfigure(0, weight=1)
        win.rowconfigure(0, weight=1)

        text = scrolledtext.ScrolledText(win, wrap=tk.WORD, font=("Consolas", 10))
        text.grid(row=0, column=0, sticky="nsew", padx=8, pady=8)
        text.insert(tk.END, self._INSTALL_HELP_TEXT)
        text.configure(state="disabled")

        close_btn = ttk.Button(win, text="Close", command=win.destroy)
        close_btn.grid(row=1, column=0, pady=(0, 8))

    def _apply_key_manager_admin_gate(self) -> None:
        if self._is_admin:
            return
        self.km_capabilities_var.set("Unavailable (administrator rights required)")
        self.km_status_var.set(admin_required_message("Backup Manager"))
        for widget in self._key_manager_widgets:
            widget.state(["disabled"])

    def _require_key_manager_admin(self) -> bool:
        if self._is_admin:
            return True
        messagebox.showerror("OpenPicoKeys", admin_required_message("Backup Manager"))
        self._apply_key_manager_admin_gate()
        return False

    @staticmethod
    def _format_capabilities_text(caps) -> str:
        return (
            f"Export supported: {'yes' if caps.export_supported else 'no'}\n"
            f"Restore supported: {'yes' if caps.restore_supported else 'no'}\n"
            f"Device ID: {caps.device_id or '(unknown)'}\n"
            f"Firmware: {caps.firmware_version or '(unknown)'}\n"
            f"Info: {caps.message or '(none)'}"
        )

    def _handle_km_caps(self, payload: object) -> None:
        if payload is None:
            return
        self.km_capabilities_var.set(self._format_capabilities_text(payload))

    def _on_km_probe(self) -> None:
        if not self._require_key_manager_admin():
            return

        def worker() -> None:
            self._post("km_status", "Probing device capabilities...")
            caps = self._km_service.probe_device()
            self._post("km_caps", caps)
            self._post("km_status", "Device probe complete")

        self._start_background(worker)

    def _on_km_backup(self) -> None:
        if not self._require_key_manager_admin():
            return
        password = self.km_password_var.get()
        if not password:
            messagebox.showerror("OpenPicoKeys", "Enter an encryption password first.")
            return

        target = filedialog.asksaveasfilename(
            title="Save encrypted key backup",
            defaultextension=".picokeybackup",
            filetypes=[("OpenPicoKeys backup", "*.picokeybackup"), ("All files", "*.*")],
        )
        if not target:
            return
        target_path = Path(target)

        def worker() -> None:
            self._post("km_status", "Creating encrypted backup...")
            saved = self._km_service.backup_to_file(target_path, password)
            self._post("km_status", f"Backup saved: {saved}")
            self._post("success", f"Encrypted backup created: {saved}")
            self._post("info", f"Encrypted backup created:\n{saved}")

        self._start_background(worker)

    def _on_km_restore(self) -> None:
        if not self._require_key_manager_admin():
            return
        password = self.km_password_var.get()
        if not password:
            messagebox.showerror("OpenPicoKeys", "Enter the backup password first.")
            return

        source = filedialog.askopenfilename(
            title="Select encrypted key backup",
            filetypes=[("OpenPicoKeys backup", "*.picokeybackup"), ("All files", "*.*")],
        )
        if not source:
            return

        proceed = messagebox.askyesno(
            "Restore backup",
            "Restore encrypted backup data to the connected Pico key?\n\n"
            "This may overwrite existing credential data depending on firmware behavior.",
        )
        if not proceed:
            return
        source_path = Path(source)

        def worker() -> None:
            self._post("km_status", "Restoring backup to device...")
            self._km_service.restore_from_file(source_path, password)
            self._post("km_status", "Restore complete")
            self._post("success", "Backup restore completed")
            self._post("info", "Backup restore completed successfully.")

        self._start_background(worker)

    def _on_km_preview(self) -> None:
        if not self._require_key_manager_admin():
            return
        password = self.km_password_var.get()
        if not password:
            messagebox.showerror("OpenPicoKeys", "Enter the backup password first.")
            return

        source = filedialog.askopenfilename(
            title="Select encrypted key backup",
            filetypes=[("OpenPicoKeys backup", "*.picokeybackup"), ("All files", "*.*")],
        )
        if not source:
            return
        source_path = Path(source)

        def worker() -> None:
            self._post("km_status", "Reading backup metadata...")
            preview = self._km_service.metadata_json(source_path, password)
            self._post("km_log", "Backup metadata preview:")
            for line in preview.splitlines():
                self._post("km_log", line)
            self._post("km_status", "Backup metadata loaded")

        self._start_background(worker)

    def _on_cust_browse_input(self) -> None:
        selected = filedialog.askopenfilename(
            title="Select optional input UF2 firmware",
            filetypes=[("UF2 firmware", "*.uf2"), ("All files", "*.*")],
        )
        if selected:
            self.cust_input_var.set(selected)

    def _on_cust_browse_cache(self) -> None:
        """Open a file dialog starting in the .picokeys/builds cache."""
        selected = filedialog.askopenfilename(
            title="Select cached UF2 build",
            initialdir=str(self._cache_dir),
            filetypes=[("UF2 firmware", "*.uf2"), ("All files", "*.*")],
        )
        if selected:
            self.cust_input_var.set(selected)

    def _on_cust_browse_output(self) -> None:
        selected = filedialog.asksaveasfilename(
            title="Save custom UF2 firmware",
            defaultextension=".uf2",
            filetypes=[("UF2 firmware", "*.uf2"), ("All files", "*.*")],
        )
        if selected:
            self.cust_output_var.set(selected)

    def _on_cust_scan(self) -> None:
        input_path = self.cust_input_var.get().strip()
        if not input_path:
            messagebox.showerror(
                "OpenPicoKeys",
                "No input UF2 selected.\n\n"
                "Input UF2 is optional for Apply/Quick Install, but scanning requires an existing UF2 file.",
            )
            return
        path = Path(input_path)
        if not path.is_file():
            messagebox.showerror("OpenPicoKeys", f"File not found:\n{path}")
            return

        def worker() -> None:
            self._post("cust_log", f"Scanning {path.name} ...")
            self._post("status", "Scanning firmware...")
            flat, info = self._cust_service.read_uf2(path)
            self._post("cust_log", f"Read {info.total_size:,} bytes  |  Board: {info.board}")
            custom = self._cust_service.scan_customization(flat)
            self._post("cust_scanned", (flat, info, custom))
            self._post("success", "UF2 scanned")

        self._start_background(worker)

    def _handle_cust_scanned(self, payload: object) -> None:
        if not isinstance(payload, tuple) or len(payload) != 3:
            return
        flat, info, custom = payload
        _ = flat

        self.cust_key_name_var.set(custom.key_name)
        self.cust_manufacturer_var.set(custom.manufacturer)
        self.cust_website_var.set(custom.website)
        self.cust_vid_var.set(f"0x{custom.usb_vid:04X}" if custom.usb_vid else "")
        self.cust_pid_var.set(f"0x{custom.usb_pid:04X}" if custom.usb_pid else "")
        self.cust_board_var.set(info.board)

        # Pre-fill output path
        if not self.cust_output_var.get().strip():
            inp = Path(self.cust_input_var.get())
            self.cust_output_var.set(
                str(inp.with_name(inp.stem + "-optimized" + inp.suffix))
            )

        parts: list[str] = [f"Board: {info.board}", f"Size: {info.total_size:,} bytes"]
        if custom.usb_vid:
            parts.append(f"VID: 0x{custom.usb_vid:04X}")
        if custom.usb_pid:
            parts.append(f"PID: 0x{custom.usb_pid:04X}")
        if custom.key_name:
            parts.append(f"Product: {custom.key_name}")
        if not custom.key_name and not custom.manufacturer:
            parts.append(
                "Strings not auto-detected \u2014 enter values or load a profile"
            )
        self.cust_status_var.set(" | ".join(parts))

        # Log detected descriptor values
        self._append_cust_log("Scan complete — detected descriptor values:")
        if custom.key_name:
            self._append_cust_log(f"  Product:      {custom.key_name}")
        if custom.manufacturer:
            self._append_cust_log(f"  Manufacturer: {custom.manufacturer}")
        if custom.website:
            self._append_cust_log(f"  Website:      {custom.website}")
        if custom.usb_vid:
            self._append_cust_log(f"  USB VID:      0x{custom.usb_vid:04X}")
        if custom.usb_pid:
            self._append_cust_log(f"  USB PID:      0x{custom.usb_pid:04X}")
        if not custom.key_name and not custom.manufacturer:
            self._append_cust_log("  (Strings not auto-detected — enter values or load a profile)")

    def _on_cust_load_profile(self) -> None:
        source = filedialog.askopenfilename(
            title="Load build profile for current values",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")],
        )
        if not source:
            return
        try:
            payload = json.loads(Path(source).read_text(encoding="utf-8"))
            profile = BuildProfile.from_dict(payload)
        except (json.JSONDecodeError, OSError, TypeError, ValueError) as exc:
            messagebox.showerror("OpenPicoKeys", f"Failed to load profile:\n{exc}")
            return

        self._apply_profile_to_customizer_fields(profile)
        self.cust_status_var.set(f"Loaded profile values from: {source}")

    def _save_cust_profile(self) -> None:
        """Save the Key Customizer form values as a profile JSON."""
        target = filedialog.asksaveasfilename(
            title="Save customizer profile",
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")],
        )
        if not target:
            return
        data = {
            "key_name": self.cust_key_name_var.get().strip(),
            "manufacturer": self.cust_manufacturer_var.get().strip(),
            "website": self.cust_website_var.get().strip(),
            "usb_vid": self.cust_vid_var.get().strip(),
            "usb_pid": self.cust_pid_var.get().strip(),
            "board": self.cust_board_var.get().strip(),
            "source_dir": "",
            "pico_sdk_path": "",
            "output_uf2": self.cust_output_var.get().strip(),
            "disable_led": self.cust_disable_led_var.get(),
        }
        path = Path(target)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8"
        )
        self.cust_status_var.set(f"Profile saved: {path}")

    # ------------------------------------------------------------------ #
    #  Quick Install helpers                                                #
    # ------------------------------------------------------------------ #

    _RPI_DRIVE_LABEL = "RPI-RP2"

    @staticmethod
    def _find_pico_drive() -> Path | None:
        """Return the mount-point of the RPI-RP2 mass-storage drive, or *None*."""
        system = platform.system()
        if system == "Windows":
            import ctypes
            bitmask = ctypes.windll.kernel32.GetLogicalDrives()  # type: ignore[union-attr]
            for letter_idx in range(26):
                if not (bitmask & (1 << letter_idx)):
                    continue
                drive = Path(f"{chr(65 + letter_idx)}:\\")
                label_buf = ctypes.create_unicode_buffer(256)
                ok = ctypes.windll.kernel32.GetVolumeInformationW(  # type: ignore[union-attr]
                    str(drive), label_buf, 256,
                    None, None, None, None, 0,
                )
                if ok and label_buf.value == OpenPicoKeysApp._RPI_DRIVE_LABEL:
                    return drive
        elif system == "Darwin":
            vol = Path("/Volumes") / OpenPicoKeysApp._RPI_DRIVE_LABEL
            if vol.is_dir():
                return vol
        else:  # Linux / BSD
            import subprocess
            try:
                out = subprocess.check_output(
                    ["lsblk", "-o", "MOUNTPOINT,LABEL", "-rn"],
                    text=True, timeout=5,
                )
                for line in out.strip().splitlines():
                    parts = line.split(None, 1)
                    if len(parts) == 2 and parts[1] == OpenPicoKeysApp._RPI_DRIVE_LABEL:
                        mp = Path(parts[0])
                        if mp.is_dir():
                            return mp
            except (FileNotFoundError, subprocess.SubprocessError):
                pass
            # Fallback: check common mount paths
            for base in ("/media", "/run/media"):
                bp = Path(base)
                if not bp.is_dir():
                    continue
                for child in bp.iterdir():
                    candidate = child / OpenPicoKeysApp._RPI_DRIVE_LABEL
                    if candidate.is_dir():
                        return candidate
        return None

    def _copy_uf2_to_pico(self, uf2_path: Path, log_fn) -> None:
        """Detect the Pico drive and copy *uf2_path* to it."""
        log_fn("Searching for Pico in BOOTSEL mode (RPI-RP2 drive)...")
        drive = self._find_pico_drive()
        if drive is None:
            raise BuildError(
                "RPI-RP2 drive not found.\n\n"
                "Make sure your Pico is connected in BOOTSEL mode:\n"
                "1. Unplug the Pico\n"
                "2. Hold the BOOTSEL button\n"
                "3. Plug it back in while holding the button\n"
                "4. Release the button — the RPI-RP2 drive should appear"
            )
        dest = drive / uf2_path.name
        log_fn(f"Pico drive found at {drive}")
        log_fn(f"Copying {uf2_path.name} ({uf2_path.stat().st_size:,} bytes) ...")
        shutil.copy2(uf2_path, dest)
        log_fn("Firmware copied — the Pico will reboot automatically.")

    def _builder_profile_changed(self, profile: BuildProfile) -> bool:
        """Return *True* if the current profile differs from the last build."""
        if self._last_built_profile is None:
            return True
        return profile.to_dict() != self._last_built_profile

    def _collect_customizer_build_profile(self) -> BuildProfile:
        """Collect build settings for Firmware Customizer quick install.

        This path intentionally does not use an input UF2 file.
        """
        board = self.cust_board_var.get().strip()
        if board not in {"pico", "pico2"}:
            board = self.board_var.get().strip() or "pico"

        profile = BuildProfile(
            source_dir=self.source_var.get().strip(),
            pico_sdk_path=self.sdk_var.get().strip(),
            output_uf2=self.cust_output_var.get().strip() or self.output_var.get().strip(),
            board=board,
            key_name=self.cust_key_name_var.get().strip() or self.key_name_var.get().strip(),
            manufacturer=self.cust_manufacturer_var.get().strip() or self.manufacturer_var.get().strip(),
            website=self.cust_website_var.get().strip() or self.website_var.get().strip(),
            usb_vid=self.cust_vid_var.get().strip() or self.usb_vid_var.get().strip(),
            usb_pid=self.cust_pid_var.get().strip() or self.usb_pid_var.get().strip(),
            disable_led=self.cust_disable_led_var.get(),
        )
        if not profile.source_dir:
            raise BuildError("Source path is required.")
        return profile

    def _on_quick_install_builder(self) -> None:
        """Build (if needed) and flash the UF2 from the Firmware Builder tab."""
        proceed = messagebox.askyesno(
            "Quick Install — Data Warning",
            "Flashing a full firmware build will ERASE all passkeys and "
            "credentials stored on the Pico.\n\n"
            "If you only want to change USB descriptors (name, VID/PID, etc.) "
            "without losing your data, use the Key Customizer tab instead.\n\n"
            "Continue with Quick Install?",
        )
        if not proceed:
            return

        try:
            profile = self._collect_profile()
        except BuildError as exc:
            messagebox.showerror("OpenPicoKeys", str(exc))
            return

        output = Path(profile.output_uf2).expanduser().resolve()
        needs_rebuild = self._builder_profile_changed(profile) or not output.is_file()

        def worker() -> None:
            log = lambda line: self._post("log", line)  # noqa: E731

            if needs_rebuild:
                if output.is_file():
                    log("Profile changed since last build — rebuilding...")
                else:
                    log("No UF2 found — starting build...")
                self._post("status", "Building firmware...")
                builder = FirmwareBuilder(log_callback=log)
                result = builder.build(profile)
                self._last_built_profile = profile.to_dict()
                self._cache_uf2(result.output_uf2, profile.key_name or "firmware", log)
                log(f"Build complete: {result.output_uf2}")
            else:
                log(f"Profile unchanged — reusing existing UF2: {output}")

            self._post("status", "Installing firmware to Pico...")
            self._copy_uf2_to_pico(output, log)
            self._post("success", "Firmware installed!")
            self._post("info", "Firmware installed successfully!\nThe Pico will reboot momentarily.")

        self._start_background(worker)

    def _on_quick_install_cust(self) -> None:
        """Flash the customized UF2 from the Key Customizer tab."""
        if not self._require_key_manager_admin():
            return

        try:
            profile = self._collect_customizer_build_profile()
        except BuildError as exc:
            messagebox.showerror("OpenPicoKeys", str(exc))
            return

        output = profile.output_path_or_default(profile.board)

        def worker() -> None:
            log = lambda line: self._post("cust_log", line)  # noqa: E731

            password = secrets.token_urlsafe(32)
            backup_dir = Path(tempfile.gettempdir()) / "openpicokeys"
            backup_dir.mkdir(parents=True, exist_ok=True)
            stamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
            backup_path = backup_dir / f"customizer-auto-backup-{stamp}.picokeybackup"
            saved_backup: Path | None = None
            restored = False

            self._post("status", "Creating encrypted backup before install...")
            caps = self._km_service.probe_device()
            if not caps.export_supported or not caps.restore_supported:
                raise KeyManagerError(
                    caps.message
                    or "Device must support both backup export and restore import for customizer quick install."
                )

            try:
                saved_backup = self._km_service.backup_to_file(backup_path, password)
                log("Temporary encrypted backup created.")

                log("Building new firmware for customizer install (no patching)...")
                self._post("status", "Building firmware for customizer install...")
                builder = FirmwareBuilder(log_callback=log)
                result = builder.build(profile)
                output = result.output_uf2
                self._last_cust_build_profile = profile.to_dict()
                self._cache_uf2(output, profile.key_name or "customizer", log)
                log(f"Build complete: {output}")

                self._wait_for_bootsel_confirmation(log)

                try:
                    self._post("status", "Installing firmware to Pico...")
                    self._copy_uf2_to_pico(output, log)
                except Exception as exc:
                    raise BuildError(
                        "Firmware copy failed after backup was created.\n\n"
                        f"Temporary backup file: {saved_backup}\n"
                        "You can restore it manually from the Backup Manager tab.\n"
                        f"Generated backup password: {password}\n\n"
                        f"Details: {exc}"
                    ) from exc

                self._post("status", "Restoring backup after install...")
                assert saved_backup is not None
                self._restore_backup_with_retry(saved_backup, password, log)
                restored = True
                self._post("cust_status", "Firmware installed and backup restored!")
                self._post("success", "Firmware installed and data restored")
                self._post(
                    "info",
                    "Firmware installed successfully and credential backup restored.",
                )
            finally:
                if saved_backup is not None and saved_backup.exists() and restored:
                    try:
                        saved_backup.unlink()
                        log("Temporary backup file removed.")
                    except OSError:
                        log(f"Warning: could not remove temporary backup file: {saved_backup}")

        self._start_background(worker)

    def _wait_for_bootsel_confirmation(self, log_fn) -> None:
        """Prompt the user to enter BOOTSEL mode and block until they confirm/cancel."""
        evt = threading.Event()
        self._bootsel_prompt_event = evt
        self._bootsel_prompt_result = False
        self._post("cust_bootsel_prompt", "")
        log_fn("Waiting for user to enable BOOTSEL mode...")
        evt.wait()
        self._bootsel_prompt_event = None
        if not self._bootsel_prompt_result:
            raise BuildError("Installation canceled by user before BOOTSEL install step.")

    def _restore_backup_with_retry(self, source: Path, password: str, log_fn) -> None:
        """Restore backup after firmware flash, retrying while the device reconnects."""
        attempts = 15
        delay_s = 2.0
        last_error: KeyManagerError | None = None

        for attempt in range(1, attempts + 1):
            try:
                self._km_service.restore_from_file(source, password)
                log_fn(f"Backup restored from: {source}")
                return
            except KeyManagerError as exc:
                last_error = exc
                if attempt < attempts:
                    log_fn(
                        f"Restore attempt {attempt}/{attempts} not ready yet: {exc}"
                    )
                    time.sleep(delay_s)
                    continue

        raise KeyManagerError(
            "Firmware was installed, but automatic restore failed after multiple retries.\n\n"
            f"Backup file is safe at: {source}\n"
            "You can restore it manually from the Backup Manager tab once the key is ready.\n\n"
            f"Last error: {last_error}"
        )


def run() -> None:
    app = OpenPicoKeysApp()
    app.mainloop()
