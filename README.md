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

## Requirements

- Python 3.10+
- `cmake`
- `ninja`
- Pico toolchain required by upstream `pico-fido` build
- Pico SDK is auto-downloaded and managed by OpenPicoKeys if `PICO_SDK_PATH` is not set

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
If one is missing, the app prompts you and offers an auto-install action.

OpenPicoKeys does not require `git`; upstream resources are downloaded as zip archives.

## License

This OpenPicoKeys GUI/tooling in this repository is MIT licensed (see `LICENSE`).

Important: generated firmware is built from upstream `pico-fido` / `pico-keys-sdk`, which are licensed under AGPLv3 in their community editions. Review upstream licensing before distribution.
