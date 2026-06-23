#!/sbin/sh
# DirtySepolicy Duck KPM Loader - safe ordinary module.
SKIPUNZIP=0

ui_print "- DirtySepolicy Duck KPM Loader v0.1.0"
ui_print "- This package does NOT autoload KPM by default."
ui_print "- Put built .kpm files in $MODPATH/kpm/ and test manual Load first."
ui_print "- Create /data/adb/dirtysepolicy_kpm/enable-autoload only after manual load is proven safe."

mkdir -p "$MODPATH/kpm" "$MODPATH/scripts"
set_perm_recursive "$MODPATH" 0 0 0755 0644
set_perm_recursive "$MODPATH/scripts" 0 0 0755 0755
set_perm "$MODPATH/service.sh" 0 0 0755
set_perm "$MODPATH/action.sh" 0 0 0755
set_perm "$MODPATH/uninstall.sh" 0 0 0755

ui_print "- Installed as a safe loader. No reboot-side KPM load unless explicitly enabled."
