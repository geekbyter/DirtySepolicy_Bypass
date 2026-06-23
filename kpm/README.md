# DirtySepolicy Duck KPM

This directory contains the non-Zygisk path for SuKiSU/KernelPatch.

## Targets

- `smoke/`: no-op KPM used to verify that the device can load KPM safely.
- `dirtyduck/`: SELinux query filter derived from `Admirepowered/selinux_hook`, adapted for DirtySepolicy/DuckDetector probes.

## Safety Order

1. Build both KPMs.
2. Load `dirtyduck_smoke_*.kpm` manually from the manager or a known-good KPM loader.
3. Check `dmesg`/kernel logs for `[dirtyduck_smoke] init`.
4. Reboot once and confirm the smoke KPM is gone or unloadable.
5. Only then load `dirtyduck_selinux_*.kpm` manually.
6. Do not enable persistent loading until the manual load path is clean.

## Build

The Makefiles expect a KernelPatch source tree at `../../../_refs/selinux_hook/KernelPatch` by default.
Override it with `KP_DIR=/path/to/KernelPatch` if needed.

On Linux/WSL:

```sh
export ANDROID_NDK_HOME=/path/to/android-ndk
make -C DirtySepolicy_Bypass/kpm/smoke
make -C DirtySepolicy_Bypass/kpm/dirtyduck
```

The current Windows PowerShell environment has Android NDK installed but no native `make`/`clang` in PATH, so WSL or CI is the intended build surface.
