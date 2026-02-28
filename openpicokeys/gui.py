from __future__ import annotations

import json
import os
import queue
import sys
import threading
import traceback
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, scrolledtext, ttk

from .builder import BuildError, FirmwareBuilder
from .models import BuildProfile


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

        self._interactive_widgets: list[ttk.Widget] = []
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

        key_customizer_tab.columnconfigure(0, weight=1)
        key_customizer_tab.rowconfigure(0, weight=1)
        ttk.Label(
            key_customizer_tab,
            text="Key customizer placeholder.\nThis tab will host key customization tools.",
            justify="center",
        ).grid(row=0, column=0, sticky="nsew", padx=16, pady=16)

        key_reader_tab.columnconfigure(0, weight=1)
        key_reader_tab.rowconfigure(0, weight=1)
        ttk.Label(
            key_reader_tab,
            text="Key Reader placeholder.\nThis tab will host key inspection and read utilities.",
            justify="center",
        ).grid(row=0, column=0, sticky="nsew", padx=16, pady=16)

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

    def _start_background(self, worker) -> None:
        if self._worker is not None and self._worker.is_alive():
            messagebox.showwarning("OpenPicoKeys", "A task is already running.")
            return

        def runner() -> None:
            try:
                worker()
            except BuildError as exc:
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
