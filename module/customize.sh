#!/sbin/sh
# DirtySepolicy Bypass - Module installer (Magisk / KernelSU / APatch)
SKIPUNZIP=0

if [ -n "$KSU" ]; then
  ROOT_SOL="KernelSU"
  ROOT_VER="$KSU_VER"
elif [ -n "$APATCH" ]; then
  ROOT_SOL="APatch"
  ROOT_VER="$APATCH_VER"
elif [ -n "$MAGISK_VER" ]; then
  ROOT_SOL="Magisk"
  ROOT_VER="$MAGISK_VER"
  if [ "$ZYGISK_ENABLED" != "true" ] && [ "$ZYGISK_ENABLED" != "1" ]; then
    if [ -f /data/adb/magisk.db ]; then
      z=$(magisk --sqlite "SELECT value FROM settings WHERE key='zygisk'" 2>/dev/null | sed 's/.*=//')
      if [ "$z" != "1" ]; then
        ui_print "! Zygisk is not enabled."
        ui_print "! Enable it in Magisk -> Settings -> Zygisk, then reflash."
        abort  "! Aborting"
      fi
    fi
  fi
else
  ROOT_SOL="Unknown"
  ROOT_VER="?"
fi

ui_print "- DirtySepolicy Bypass v5.0.2-targeted"
ui_print "- Root: $ROOT_SOL $ROOT_VER"
ui_print "- ABI: $ARCH ($IS64BIT-bit)"

case "$ARCH" in
  arm64)   ABI_LIB=arm64-v8a   ;;
  arm)     ABI_LIB=armeabi-v7a ;;
  x64)     ABI_LIB=x86_64      ;;
  x86)     ABI_LIB=x86         ;;
  *)       abort "! Unsupported ABI: $ARCH" ;;
esac

if [ ! -f "$MODPATH/zygisk/$ABI_LIB.so" ]; then
  ui_print "! Missing zygisk/$ABI_LIB.so in module zip"
  abort  "! Aborting"
fi

set_perm_recursive "$MODPATH" 0 0 0755 0644
set_perm_recursive "$MODPATH/zygisk" 0 0 0755 0755

ui_print "- Reboot to activate."
