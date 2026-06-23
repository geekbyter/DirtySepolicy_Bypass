#!/system/bin/sh
MODDIR=${0%/*}
STATE_DIR=/data/adb/dirtysepolicy_kpm
LOG="$STATE_DIR/service.log"

mkdir -p "$STATE_DIR"

log() {
  echo "$(date '+%Y-%m-%d %H:%M:%S') $*" >> "$LOG"
}

if [ -f "$MODDIR/disable" ] || [ -f "$STATE_DIR/disable" ]; then
  log "disabled by marker"
  exit 0
fi

if [ ! -f "$STATE_DIR/enable-autoload" ]; then
  log "autoload not enabled; skip KPM load"
  exit 0
fi

KPM="$MODDIR/kpm/dirtyduck_selinux.kpm"
if [ ! -f "$KPM" ]; then
  log "missing $KPM; skip"
  exit 0
fi

log "autoload requested; loading $KPM"
sh "$MODDIR/scripts/load-kpm.sh" "$KPM" >> "$LOG" 2>&1
RC=$?
log "load finished rc=$RC"
exit 0
