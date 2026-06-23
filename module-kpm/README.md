# DirtySepolicy Duck KPM Loader

This ordinary module is intentionally safe by default:

- It does not contain Zygisk libraries.
- It does not autoload KPM after installation.
- It only autoloads when `/data/adb/dirtysepolicy_kpm/enable-autoload` exists.

## Manual Test Flow

1. Build `kpm/smoke` and load `dirtyduck_smoke_*.kpm` manually from the manager.
2. Confirm kernel logs contain `[dirtyduck_smoke] init`.
3. Build `kpm/dirtyduck` and load `dirtyduck_selinux_*.kpm` manually.
4. Run the SELinux audit and DuckDetector.
5. Only after manual load is stable, copy the built file to `module-kpm/kpm/dirtyduck_selinux.kpm` and enable autoload:

```sh
su -c 'mkdir -p /data/adb/dirtysepolicy_kpm; touch /data/adb/dirtysepolicy_kpm/enable-autoload'
```

## Emergency Disable

```sh
su -c 'touch /data/adb/dirtysepolicy_kpm/disable; rm -f /data/adb/dirtysepolicy_kpm/enable-autoload'
```
