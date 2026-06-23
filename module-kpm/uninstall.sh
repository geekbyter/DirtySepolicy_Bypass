#!/system/bin/sh
STATE_DIR=/data/adb/dirtysepolicy_kpm

rm -f "$STATE_DIR/enable-autoload"
touch "$STATE_DIR/disable"
echo "DirtySepolicy Duck KPM autoload disabled."
