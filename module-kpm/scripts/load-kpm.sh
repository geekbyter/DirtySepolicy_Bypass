#!/system/bin/sh
KPM="$1"

if [ -z "$KPM" ] || [ ! -f "$KPM" ]; then
  echo "usage: $0 /path/to/module.kpm"
  exit 2
fi

try_cmd() {
  BIN="$1"
  shift
  if command -v "$BIN" >/dev/null 2>&1 || [ -x "$BIN" ]; then
    echo "try: $BIN $*"
    "$BIN" "$@" && exit 0
  fi
}

# SuKiSU/KernelSU userspace builds have used ksud for KPM management.
# Keep this script transient-only: do not call install/embed/autoload here.
try_cmd /data/adb/ksud kpm load "$KPM"
try_cmd /data/adb/ksu/bin/ksud kpm load "$KPM"
try_cmd ksud kpm load "$KPM"

# APatch/KernelPatch style fallback. Some builds expose kp in PATH.
try_cmd /data/adb/ap/bin/kp load "$KPM"
try_cmd /data/adb/ksu/bin/kp load "$KPM"
try_cmd kp load "$KPM"

echo "No known transient KPM loader succeeded."
echo "Load the KPM manually from SuKiSU/APatch manager, then check dmesg."
exit 1
