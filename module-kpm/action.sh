#!/system/bin/sh
MODDIR=${0%/*}
STATE_DIR=/data/adb/dirtysepolicy_kpm

mkdir -p "$STATE_DIR"

echo "DirtySepolicy Duck KPM Loader"
echo "State dir: $STATE_DIR"
echo
echo "This action only prints status; it does not load KPM."
echo "Manual test order:"
echo "  1. Load smoke KPM from SuKiSU/APatch manager."
echo "  2. Check dmesg for [dirtyduck_smoke]."
echo "  3. Load dirtyduck_selinux KPM manually."
echo "  4. Only after success: touch $STATE_DIR/enable-autoload"
echo
echo "Module files:"
ls -l "$MODDIR/kpm" 2>/dev/null || true
echo
echo "Recent loader log:"
tail -n 80 "$STATE_DIR/service.log" 2>/dev/null || echo "(no log yet)"
