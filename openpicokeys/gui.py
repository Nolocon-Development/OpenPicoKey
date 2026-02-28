from __future__ import annotations

import json
import os
import platform
import queue
import shutil
import sys
import threading
import traceback
import tkinter as tk
from datetime import datetime
from pathlib import Path
from tkinter import filedialog, messagebox, scrolledtext, ttk

from .builder import BuildError, FirmwareBuilder
from .models import BuildProfile
from .customizer import FirmwareCustomization, FirmwareCustomizer, CustomizerError, UF2Info


class OpenPicoKeysApp(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title("OpenPicoKeys")
        self.geometry("980x760")
        self.minsize(900, 700)

        self._events: queue.Queue[tuple[str, object]] = queue.Queue()
        self._worker: threading.Thread | None = None
        self._busy = False

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
        self._last_cust_applied: dict | None = None

        # Customizer state
        self._cust_service = FirmwareCustomizer(
            log_callback=lambda line: self._post("log", line),
        )
        self._cust_current: FirmwareCustomization | None = None
        self._cust_flat: bytearray | None = None
        self._cust_info: UF2Info | None = None

        self.cust_input_var = tk.StringVar(value="")
        self.cust_output_var = tk.StringVar(value="")
        self.cust_key_name_var = tk.StringVar(value="")
        self.cust_manufacturer_var = tk.StringVar(value="")
        self.cust_website_var = tk.StringVar(value="")
        self.cust_vid_var = tk.StringVar(value="")
        self.cust_pid_var = tk.StringVar(value="")
        self.cust_status_var = tk.StringVar(value="Load a UF2 firmware file to begin.")

        self._interactive_widgets: list[ttk.Widget] = []
        self._cache_dir = Path.cwd() / ".picokeys" / "builds"
        self._cache_dir.mkdir(parents=True, exist_ok=True)
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
            text="OpenPicoKeys - Open source PicoKey customizer & manager",
            font=("Segoe UI", 13, "bold"),
        )
        header.grid(row=0, column=0, sticky="w")

        notebook = ttk.Notebook(root)
        notebook.grid(row=1, column=0, sticky="nsew", pady=(10, 0))
        self._notebook = notebook

        firmware_tab = ttk.Frame(notebook)
        key_customizer_tab = ttk.Frame(notebook)
        notebook.add(firmware_tab, text="Firmware Builder")
        notebook.add(key_customizer_tab, text="Key Customizer")

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

        # ---- Key Customizer tab ----
        key_customizer_tab.columnconfigure(0, weight=1)
        key_customizer_tab.rowconfigure(0, weight=1)

        cust_root = ttk.Frame(key_customizer_tab, padding=8)
        cust_root.grid(row=0, column=0, sticky="nsew")
        cust_root.columnconfigure(0, weight=1)
        cust_root.rowconfigure(3, weight=1)

        cust_subtitle = ttk.Label(
            cust_root,
            text="Step 1: Select firmware  |  Step 2: Customize descriptors  |  Step 3: Apply changes",
        )
        cust_subtitle.grid(row=0, column=0, sticky="w", pady=(2, 12))

        src_frame = ttk.LabelFrame(cust_root, text="Step 1 - Source Firmware")
        src_frame.grid(row=1, column=0, sticky="ew")
        src_frame.columnconfigure(1, weight=1)

        ttk.Label(src_frame, text="Input UF2").grid(
            row=0, column=0, padx=6, pady=6, sticky="w"
        )
        cust_input_entry = ttk.Entry(src_frame, textvariable=self.cust_input_var)
        cust_input_entry.grid(row=0, column=1, padx=6, pady=6, sticky="ew")
        cust_browse_input_btn = ttk.Button(
            src_frame, text="Browse", command=self._on_cust_browse_input
        )
        cust_browse_input_btn.grid(row=0, column=2, padx=6, pady=6)
        cust_scan_btn = ttk.Button(
            src_frame, text="Scan UF2", command=self._on_cust_scan
        )
        cust_scan_btn.grid(row=0, column=3, padx=6, pady=6)
        cust_cache_btn = ttk.Button(
            src_frame, text="From Cache", command=self._on_cust_browse_cache
        )
        cust_cache_btn.grid(row=0, column=4, padx=6, pady=6)

        desc_frame = ttk.LabelFrame(cust_root, text="Step 2 - Descriptor Customization")
        desc_frame.grid(row=2, column=0, sticky="ew", pady=(12, 0))
        for c in range(4):
            desc_frame.columnconfigure(c, weight=1)

        ttk.Label(desc_frame, text="Key Name (USB product)").grid(
            row=0, column=0, padx=6, pady=6, sticky="w"
        )
        cust_key_name_entry = ttk.Entry(
            desc_frame, textvariable=self.cust_key_name_var
        )
        cust_key_name_entry.grid(row=0, column=1, padx=6, pady=6, sticky="ew")
        ttk.Label(desc_frame, text="Manufacturer").grid(
            row=0, column=2, padx=6, pady=6, sticky="w"
        )
        cust_manufacturer_entry = ttk.Entry(
            desc_frame, textvariable=self.cust_manufacturer_var
        )
        cust_manufacturer_entry.grid(row=0, column=3, padx=6, pady=6, sticky="ew")

        ttk.Label(desc_frame, text="Website (WebUSB URL)").grid(
            row=1, column=0, padx=6, pady=6, sticky="w"
        )
        cust_website_entry = ttk.Entry(
            desc_frame, textvariable=self.cust_website_var
        )
        cust_website_entry.grid(
            row=1, column=1, columnspan=3, padx=6, pady=6, sticky="ew"
        )

        ttk.Label(desc_frame, text="USB VID").grid(
            row=2, column=0, padx=6, pady=6, sticky="w"
        )
        cust_vid_entry = ttk.Entry(desc_frame, textvariable=self.cust_vid_var)
        cust_vid_entry.grid(row=2, column=1, padx=6, pady=6, sticky="ew")
        ttk.Label(desc_frame, text="USB PID").grid(
            row=2, column=2, padx=6, pady=6, sticky="w"
        )
        cust_pid_entry = ttk.Entry(desc_frame, textvariable=self.cust_pid_var)
        cust_pid_entry.grid(row=2, column=3, padx=6, pady=6, sticky="ew")

        desc_hint = ttk.Label(
            desc_frame,
            text=(
                "Values pre-filled after scan.  Edit only what you want to change.  "
                "New strings cannot exceed the length of current firmware values."
            ),
            foreground="gray",
        )
        desc_hint.grid(
            row=3, column=0, columnspan=4, padx=6, pady=(0, 6), sticky="w"
        )

        ttk.Label(desc_frame, text="Output UF2").grid(
            row=4, column=0, padx=6, pady=6, sticky="w"
        )
        cust_output_entry = ttk.Entry(
            desc_frame, textvariable=self.cust_output_var
        )
        cust_output_entry.grid(row=4, column=1, padx=6, pady=6, sticky="ew")
        cust_browse_output_btn = ttk.Button(
            desc_frame, text="Browse", command=self._on_cust_browse_output
        )
        cust_browse_output_btn.grid(row=4, column=2, padx=6, pady=6)

        cust_action_frame = ttk.Frame(desc_frame)
        cust_action_frame.grid(row=4, column=3, padx=6, pady=6, sticky="e")
        cust_load_profile_btn = ttk.Button(
            cust_action_frame, text="Load Profile", command=self._on_cust_load_profile
        )
        cust_load_profile_btn.grid(row=0, column=0, padx=(0, 6))
        cust_apply_btn = ttk.Button(
            cust_action_frame, text="Apply Changes", command=self._on_cust_apply
        )
        cust_apply_btn.grid(row=0, column=1)

        cust_logs_frame = ttk.LabelFrame(cust_root, text="Customizer Log")
        cust_logs_frame.grid(row=3, column=0, sticky="nsew", pady=(12, 0))
        cust_logs_frame.columnconfigure(0, weight=1)
        cust_logs_frame.rowconfigure(0, weight=1)

        self.cust_logs = scrolledtext.ScrolledText(
            cust_logs_frame, wrap=tk.WORD, height=20
        )
        self.cust_logs.grid(row=0, column=0, sticky="nsew")
        self.cust_logs.configure(state="disabled")

        cust_status_frame = ttk.Frame(cust_root)
        cust_status_frame.grid(row=4, column=0, sticky="ew", pady=(8, 0))
        cust_status_frame.columnconfigure(0, weight=1)
        cust_status_label = ttk.Label(
            cust_status_frame, textvariable=self.cust_status_var
        )
        cust_status_label.grid(row=0, column=0, sticky="w")
        cust_quick_install_btn = ttk.Button(
            cust_status_frame, text="\u26a1 Quick Install", command=self._on_quick_install_cust
        )
        cust_quick_install_btn.grid(row=0, column=1, sticky="e", padx=(6, 0))
        cust_help_btn = ttk.Button(
            cust_status_frame, text="How to install firmware", command=self._show_install_help
        )
        cust_help_btn.grid(row=0, column=2, sticky="e", padx=(6, 0))

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
            cust_browse_input_btn,
            cust_scan_btn,
            cust_cache_btn,
            cust_load_profile_btn,
            cust_key_name_entry,
            cust_manufacturer_entry,
            cust_website_entry,
            cust_vid_entry,
            cust_pid_entry,
            cust_output_entry,
            cust_browse_output_btn,
            cust_apply_btn,
            cust_quick_install_btn,
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

    def _append_cust_log(self, message: str) -> None:
        view_before = self.cust_logs.yview()
        at_bottom = view_before[1] >= 0.999
        self.cust_logs.configure(state="normal")
        self.cust_logs.insert(tk.END, message.rstrip() + "\n")
        if at_bottom:
            self.cust_logs.see(tk.END)
        else:
            self.cust_logs.yview_moveto(view_before[0])
        self.cust_logs.configure(state="disabled")

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

        self.after(100, self._drain_events)

    def _set_busy(self, busy: bool) -> None:
        self._busy = busy
        for widget in self._interactive_widgets:
            if busy:
                widget.state(["disabled"])
            else:
                widget.state(["!disabled"])
            if isinstance(widget, ttk.Combobox):
                if not busy:
                    widget.configure(state="readonly")
                continue
        if busy:
            self.status_var.set("Working...")
        elif self.status_var.get() == "Working...":
            self.status_var.set("Ready")
        if not busy and self.status_var.get() == "Working...":
            self.status_var.set("Ready")

    def _start_background(self, worker) -> None:
        if self._worker is not None and self._worker.is_alive():
            messagebox.showwarning("OpenPicoKeys", "A task is already running.")
            return

        def runner() -> None:
            try:
                worker()
            except (BuildError, CustomizerError) as exc:
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
        cached = self._cache_dir / f"{prefix}-{stamp}.uf2"
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

    def _on_cust_browse_input(self) -> None:
        selected = filedialog.askopenfilename(
            title="Select input UF2 firmware",
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
            title="Save optimized UF2 firmware",
            defaultextension=".uf2",
            filetypes=[("UF2 firmware", "*.uf2"), ("All files", "*.*")],
        )
        if selected:
            self.cust_output_var.set(selected)

    def _on_cust_scan(self) -> None:
        input_path = self.cust_input_var.get().strip()
        if not input_path:
            messagebox.showerror("OpenPicoKeys", "Select an input UF2 file first.")
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
        self._cust_flat = flat
        self._cust_info = info
        self._cust_current = custom

        self.cust_key_name_var.set(custom.key_name)
        self.cust_manufacturer_var.set(custom.manufacturer)
        self.cust_website_var.set(custom.website)
        self.cust_vid_var.set(f"0x{custom.usb_vid:04X}" if custom.usb_vid else "")
        self.cust_pid_var.set(f"0x{custom.usb_pid:04X}" if custom.usb_pid else "")

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

        try:
            vid = (
                FirmwareCustomizer.parse_hex_word(profile.usb_vid, "USB VID")
                if profile.usb_vid.strip()
                else 0
            )
            pid = (
                FirmwareCustomizer.parse_hex_word(profile.usb_pid, "USB PID")
                if profile.usb_pid.strip()
                else 0
            )
        except CustomizerError:
            vid, pid = 0, 0

        self._cust_current = FirmwareCustomization(
            key_name=profile.key_name,
            manufacturer=profile.manufacturer,
            website=profile.website,
            usb_vid=vid,
            usb_pid=pid,
        )
        self.cust_key_name_var.set(profile.key_name)
        self.cust_manufacturer_var.set(profile.manufacturer)
        self.cust_website_var.set(profile.website)
        self.cust_vid_var.set(profile.usb_vid)
        self.cust_pid_var.set(profile.usb_pid)
        self.cust_status_var.set(f"Loaded profile values from: {source}")

    def _on_cust_apply(self) -> None:
        input_path = self.cust_input_var.get().strip()
        output_path = self.cust_output_var.get().strip()
        if not input_path:
            messagebox.showerror("OpenPicoKeys", "Select an input UF2 file first.")
            return
        if not output_path:
            messagebox.showerror("OpenPicoKeys", "Select an output UF2 file path.")
            return

        current = self._cust_current
        if current is None:
            messagebox.showerror(
                "OpenPicoKeys",
                "Scan the UF2 or load a build profile before applying changes.",
            )
            return

        try:
            new_vid = (
                FirmwareCustomizer.parse_hex_word(self.cust_vid_var.get(), "USB VID")
                if self.cust_vid_var.get().strip()
                else current.usb_vid
            )
            new_pid = (
                FirmwareCustomizer.parse_hex_word(self.cust_pid_var.get(), "USB PID")
                if self.cust_pid_var.get().strip()
                else current.usb_pid
            )
        except CustomizerError as exc:
            messagebox.showerror("OpenPicoKeys", str(exc))
            return

        new = FirmwareCustomization(
            key_name=self.cust_key_name_var.get().strip() or current.key_name,
            manufacturer=self.cust_manufacturer_var.get().strip() or current.manufacturer,
            website=self.cust_website_var.get().strip() or current.website,
            usb_vid=new_vid,
            usb_pid=new_pid,
        )

        inp = Path(input_path)
        out = Path(output_path)

        def worker() -> None:
            self._post("cust_log", f"Applying patches to {inp.name} ...")
            self._post("status", "Applying firmware patches...")
            self._cust_service.optimize(inp, out, current, new)
            self._post("cust_log", f"New values:  Product={new.key_name}  Manufacturer={new.manufacturer}")
            self._post("cust_log", f"  Website={new.website}  VID=0x{new.usb_vid:04X}  PID=0x{new.usb_pid:04X}")
            self._cache_uf2(out, new.key_name or "customized",
                            lambda line: self._post("cust_log", line))
            self._last_cust_applied = {
                "input": str(inp), "output": str(out),
                "key_name": new.key_name, "manufacturer": new.manufacturer,
                "website": new.website, "vid": new.usb_vid, "pid": new.usb_pid,
            }
            self._post("cust_status", f"Optimized UF2 saved: {out}")
            self._post("success", f"Optimized UF2: {out}")
            self._post("info", f"Optimized firmware saved:\n{out}")

        self._start_background(worker)


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

    def _cust_settings_changed(self) -> bool:
        """Return *True* if customizer form values differ from the last apply."""
        if self._last_cust_applied is None:
            return True
        output_path = self.cust_output_var.get().strip()
        current: dict[str, str | int] = {
            "input": str(Path(self.cust_input_var.get().strip()).expanduser().resolve()),
            "output": str(Path(output_path).expanduser().resolve()) if output_path else "",
            "key_name": self.cust_key_name_var.get().strip(),
            "manufacturer": self.cust_manufacturer_var.get().strip(),
            "website": self.cust_website_var.get().strip(),
        }
        # VID/PID stored as int in snapshot but as string in form — normalise
        vid_str = self.cust_vid_var.get().strip()
        pid_str = self.cust_pid_var.get().strip()
        try:
            current["vid"] = FirmwareCustomizer.parse_hex_word(vid_str, "VID") if vid_str else 0
        except CustomizerError:
            current["vid"] = -1
        try:
            current["pid"] = FirmwareCustomizer.parse_hex_word(pid_str, "PID") if pid_str else 0
        except CustomizerError:
            current["pid"] = -1
        return current != self._last_cust_applied

    def _on_quick_install_cust(self) -> None:
        """Flash the customized UF2 from the Key Customizer tab."""
        output_path = self.cust_output_var.get().strip()
        if not output_path:
            messagebox.showerror("OpenPicoKeys", "Set an output UF2 path first.")
            return
        output = Path(output_path).expanduser().resolve()

        if self._cust_settings_changed():
            # Descriptor values changed — need to re-apply before installing
            re_apply = messagebox.askyesno(
                "OpenPicoKeys",
                "Customization settings have changed since the last Apply.\n\n"
                "Apply the new changes and then install?",
            )
            if not re_apply:
                return
            # Trigger apply; user will need to Quick Install again after
            self._on_cust_apply()
            return

        if not output.is_file():
            messagebox.showerror(
                "OpenPicoKeys",
                f"Output UF2 not found:\n{output}\n\n"
                "Apply changes first to generate the customized firmware.",
            )
            return

        def worker() -> None:
            log = lambda line: self._post("cust_log", line)  # noqa: E731
            self._post("status", "Installing firmware to Pico...")
            self._copy_uf2_to_pico(output, log)
            self._post("cust_status", "Firmware installed!")
            self._post("success", "Firmware installed!")
            self._post("info", "Firmware installed successfully!\nThe Pico will reboot momentarily.")

        self._start_background(worker)


def run() -> None:
    app = OpenPicoKeysApp()
    app.mainloop()
