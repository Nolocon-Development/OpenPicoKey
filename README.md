# OpenPicoKeys

OpenPicoKeys is a lightweight, open-source Tkinter desktop app for building custom Pico FIDO firmware (`.uf2`) from the upstream `pico-fido` + `pico-keys-sdk` sources.

It is designed as an open alternative workflow to configure a Raspberry Pi Pico FIDO stick with your own:

- key name (USB product string)
- manufacturer string
- website (WebUSB URL descriptor)
- USB VID/PID
- board target (`pico` / `pico2`)
- optional LED disable

## What It Does

OpenPicoKeys provides a 3-step flow:

1. **Prepare Source**  
   Download (or reuse) pinned source archives for `pico-fido`, `pico-keys-sdk`, and required nested SDK components.
2. **Customize Device Fields**  
   Set key name + website + other metadata in the GUI.
3. **Build UF2**  
   Runs CMake build and exports a final `.uf2` firmware file.

It also includes a **Firmware Customizer** tab that mirrors the builder-style flow with backup safety:

1. Configure descriptor fields (name/manufacturer/website/VID/PID)
2. Build a new UF2 from those settings (no binary patching)
3. Install firmware and automatically restore backup data

## Requirements

- Python 3.10+
- `fido2` Python package (for Backup Manager backup/restore transport)
- `cmake`
- `ninja`
- Pico toolchain required by upstream `pico-fido` build
- Pico SDK is auto-downloaded and managed by OpenPicoKeys if `PICO_SDK_PATH` is not set

Install Python dependencies with:

```bash
pip install -r requirements.txt
```

## Run

```bash
python main.py
```

## Notes About Customization

OpenPicoKeys applies your customization to upstream SDK descriptor definitions during build, then restores the original source file after completion.

To avoid Windows host compiler issues when Pico SDK tries to build `picotool`, OpenPicoKeys builds with `PICO_NO_PICOTOOL=1` and generates UF2 directly from the produced `.bin`.

Current mapping:

- **Key Name** -> USB product descriptor
- **Manufacturer** -> USB manufacturer descriptor
- **Website** -> WebUSB URL descriptor
- **USB VID/PID** -> CMake `-DUSB_VID` / `-DUSB_PID`
- **Disable LED** -> build-time LED driver override to dummy/no-op

## Dependency Prompts

On startup, OpenPicoKeys checks required build dependencies.
If any are missing, the app prompts once, auto-installs all missing dependencies, then restarts automatically.

## Backup Manager

The `Backup Manager` tab supports:

- probing device backup/restore capabilities
- encrypted backup export to `.picokeybackup` files
- encrypted backup restore with safety checks
- metadata preview for encrypted backup files

Notes:

- backup/restore availability depends on firmware vendor-command support
- backups are encrypted with Argon2id + AES-256-GCM
- cross-device restore is blocked when device IDs do not match

## Firmware Customizer Quick Install

The Firmware Customizer quick install path performs:

1. Encrypted backup export (via Backup Manager transport)
1. Prompt to place device in BOOTSEL mode
1. UF2 build/install from current customizer settings
1. Automatic encrypted restore after firmware reboot

No binary patching is used in this flow — firmware is always rebuilt from source.

For this quick-install path, backup credentials are automated:

- a random one-time backup password is generated automatically
- the encrypted backup is saved to a temporary file during install/restore
- the temporary backup file is removed automatically after successful restore

If automatic restore cannot complete in time, the temporary backup file is preserved and the error message shows its path and generated password for manual recovery via the Backup Manager tab.

OpenPicoKeys does not require `git`; upstream resources are downloaded as zip archives.

## License

This OpenPicoKeys GUI/tooling in this repository is MIT licensed (see `LICENSE`).

Important: generated firmware is built from upstream `pico-fido` / `pico-keys-sdk`, which are licensed under AGPLv3 in their community editions. Review upstream licensing before distribution.
