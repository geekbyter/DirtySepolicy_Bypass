#!/usr/bin/env python3
"""
SELinux detection-surface audit for DirtySepolicy v2.0–v2.2.

Mirrors every probe that DirtySepolicy's AppZygote.doCheck() performs,
using the same kernel interfaces (direct selinuxfs I/O), and reports
whether the bypass module's hook tables would mask each one.

Run with root:  su -c "python3 tools/audit.py"

Output columns:
  RAW       — what the kernel returns without Zygisk hooks
  HOOK      — would the bypass module's tables mask this?
  STATUS    — BLOCKED / LEAK / absent

LEAK means the kernel confirms the probe exists AND the hook would NOT
mask it — a detector hardcoding this probe would catch you.
"""

import os
import re
import struct
import sys

# ---------- kernel selinuxfs I/O (mirrors DirtySepolicy v2.2) ---------------

SELINUXFS = "/sys/fs/selinux"


def read_index(class_name, perm_name):
    class_path = f"{SELINUXFS}/class/{class_name}/index"
    perm_path = f"{SELINUXFS}/class/{class_name}/perms/{perm_name}"
    try:
        with open(class_path) as f:
            class_id = int(f.read().strip())
        with open(perm_path) as f:
            perm_bit = 1 << (int(f.read().strip()) - 1)
        return class_id, perm_bit
    except (FileNotFoundError, ValueError):
        return None, None


def kernel_access(scon, tcon, tclass_id):
    query = f"{scon} {tcon} {tclass_id}"
    try:
        fd = os.open(f"{SELINUXFS}/access", os.O_RDWR)
        try:
            os.write(fd, query.encode())
            resp = os.read(fd, 64).decode()
        finally:
            os.close(fd)
        parts = resp.split()
        if len(parts) != 6:
            return None
        return parts
    except OSError:
        return None


def check_selinux_access(scon, tcon, tclass, perm):
    class_id, perm_bit = read_index(tclass, perm)
    if class_id is None:
        return False
    parts = kernel_access(scon, tcon, class_id)
    if parts is None:
        return False
    allowed = int(parts[0], 16)
    return (allowed & perm_bit) == perm_bit


def context_exists(context):
    # Method 1: /sys/fs/selinux/context (same as SELinux.contextExists)
    try:
        fd = os.open(f"{SELINUXFS}/context", os.O_WRONLY)
        try:
            os.write(fd, context.encode())
            return True
        except OSError as e:
            if e.errno != 22:  # EINVAL
                raise
        finally:
            os.close(fd)
    except OSError:
        pass

    # Method 2: write as scon+tcon to access with tclass=0
    try:
        fd = os.open(f"{SELINUXFS}/access", os.O_RDWR)
        try:
            os.write(fd, f"{context} {context} 0".encode())
            os.read(fd, 64)
            return True
        except OSError as e:
            if e.errno != 22:
                raise
        finally:
            os.close(fd)
    except OSError:
        pass

    # Method 3: /proc/self/attr/current
    try:
        fd = os.open("/proc/self/attr/current", os.O_WRONLY)
        try:
            os.write(fd, context.encode())
            return True
        except OSError as e:
            if e.errno == 22:   # EINVAL — context unknown
                return False
            if e.errno == 1:    # EPERM — context valid, transition denied
                return True
            raise
        finally:
            os.close(fd)
    except OSError:
        pass

    return False


def read_status():
    try:
        with open(f"{SELINUXFS}/status", "rb") as f:
            data = f.read(20)
        if len(data) < 20:
            return None
        return struct.unpack("=IIIII", data)
    except OSError:
        return None


def read_avd_seqno():
    parts = kernel_access("u:r:untrusted_app:s0", "u:r:untrusted_app:s0", 0)
    if parts is None or len(parts) < 5:
        return None
    return int(parts[4])


def detect_kernel():
    release = os.uname().release
    parts = release.split(".")
    try:
        major, minor = int(parts[0]), int(parts[1].split("-")[0])
    except (IndexError, ValueError):
        major, minor = 0, 0
    new = major > 6 or (major == 6 and minor >= 10)
    return release, new


# ---------- bypass module tables (must match jni/module.cpp) ----------------

HOOK_BLOCKLIST = [
    ":magisk", ":kitsune", ":apatch",
    ":ksu", ":kernelsu",
    ":lsposed", ":xposed", ":riru",
    ":adbroot",
    ":supersu", ":supolicy", ":su:",
    ":zygisk",
]

HOOK_HIDDEN_PERMS = ["execmem"]

HOOK_EXACT_PROBES = [
    ("u:object_r:rootfs:s0", "u:object_r:tmpfs:s0", "filesystem", "associate"),
    ("u:r:kernel:s0",        "u:object_r:tmpfs:s0", "fifo_file",  "open"),
    ("u:r:kernel:s0",        "u:object_r:adb_data_file:s0", "file", "read"),
    ("u:r:system_server:s0", "u:object_r:apk_data_file:s0", "file", "execute"),
    ("u:r:dex2oat:s0",       "u:object_r:dex2oat_exec:s0",  "file", "execute_no_trans"),
    ("u:r:zygote:s0",        "u:object_r:adb_data_file:s0", "dir",  "search"),
]


def hook_would_hide(scon, tcon, tclass=None, perm=None):
    for s in HOOK_BLOCKLIST:
        if s in scon or s in tcon:
            return True
    if perm and perm in HOOK_HIDDEN_PERMS:
        return True
    if tclass and perm:
        for es, et, ec, ep in HOOK_EXACT_PROBES:
            if scon == es and tcon == et and tclass == ec and perm == ep:
                return True
    return False


def hook_would_hide_context(context):
    for s in HOOK_BLOCKLIST:
        if s in context:
            return True
    return False


# ---------- probe definitions (mirrors AppZygote.doCheck) -------------------

CONTEXT_PROBES = [
    ("adbroot",        "u:r:adbroot:s0"),
    ("magisk",         "u:r:magisk:s0"),
    ("magisk_file",    "u:object_r:magisk_file:s0"),
    ("ksu",            "u:r:ksu:s0"),
    ("ksu_file",       "u:object_r:ksu_file:s0"),
    ("lsposed_file",   "u:object_r:lsposed_file:s0"),
    ("xposed_data",    "u:object_r:xposed_data:s0"),
    ("xposed_file",    "u:object_r:xposed_file:s0"),
]

ACCESS_PROBES = [
    ("system_server execmem",  "u:r:system_server:s0", "u:r:system_server:s0", "process",    "execmem"),
    ("AOSP su transition",     "u:r:shell:s0",         "u:r:su:s0",            "process",    "transition"),
    ("Magisk rootfs->tmpfs",   "u:object_r:rootfs:s0", "u:object_r:tmpfs:s0",  "filesystem", "associate"),
    ("Magisk kernel->tmpfs",   "u:r:kernel:s0",        "u:object_r:tmpfs:s0",  "fifo_file",  "open"),
    ("KSU kernel->adb_data",   "u:r:kernel:s0",        "u:object_r:adb_data_file:s0", "file", "read"),
    ("LSPosed apk execute",    "u:r:system_server:s0", "u:object_r:apk_data_file:s0", "file", "execute"),
    ("Xposed dex2oat exec",    "u:r:dex2oat:s0",       "u:object_r:dex2oat_exec:s0",  "file", "execute_no_trans"),
    ("ZygiskNext dir search",  "u:r:zygote:s0",        "u:object_r:adb_data_file:s0", "dir",  "search"),
]

FUTURE_PROBES = [
    ("magisk32 binder",       "u:r:untrusted_app:s0", "u:r:magisk32:s0",               "binder", "call"),
    ("magisk_log_file read",  "u:r:untrusted_app:s0", "u:object_r:magisk_log_file:s0", "file",   "read"),
    ("APatch binder",         "u:r:untrusted_app:s0", "u:r:apatch:s0",                 "binder", "call"),
    ("KitsuneMask binder",    "u:r:untrusted_app:s0", "u:r:kitsune:s0",                "binder", "call"),
    ("Riru file",             "u:r:untrusted_app:s0", "u:object_r:riru_file:s0",       "file",   "read"),
    ("SuperSU binder",        "u:r:untrusted_app:s0", "u:r:supersu:s0",                "binder", "call"),
    ("Zygisk-generic file",   "u:r:untrusted_app:s0", "u:object_r:zygisk_file:s0",     "file",   "read"),
]


# ---------- policy binary scan ---------------------------------------------

SUSPICIOUS_NAMES = [
    "magisk", "ksu", "kernelsu", "lsposed", "xposed", "riru",
    "supersu", "zygisk", "apatch", "shamiko", "kitsune", "adbroot",
    "supolicy", "su_daemon",
]

STOCK_FP = {"su"}


def scan_policy_types():
    try:
        blob = open(f"{SELINUXFS}/policy", "rb").read()
    except PermissionError:
        return None
    ids = set(m.decode("ascii", errors="ignore")
              for m in re.findall(rb"[A-Za-z_][A-Za-z0-9_]{2,63}", blob))
    out = []
    for name in sorted(ids):
        if name in STOCK_FP:
            continue
        if any(s in name.lower() for s in SUSPICIOUS_NAMES):
            out.append(name)
    return out


# ---------- presentation ---------------------------------------------------

def color(s, c):
    if not sys.stdout.isatty():
        return s
    codes = {"red": 31, "green": 32, "yellow": 33, "cyan": 36, "dim": 90}
    return f"\033[{codes[c]}m{s}\033[0m"


def status_of(exists, hook_hides):
    if exists and hook_hides:
        return color("BLOCKED", "green")
    if exists and not hook_hides:
        return color("LEAK", "red")
    if not exists and hook_hides:
        return color("(over-block)", "dim")
    return color("absent", "dim")


def main():
    release, new_kernel = detect_kernel()

    print("=" * 72)
    print("SELinux detection-surface audit (DirtySepolicy v2.0-v2.2)")
    print(f"kernel {release}  new_kernel={new_kernel}")
    print("=" * 72)
    print()

    leaks = []

    # --- context-existence probes ---
    print(f"{'CONTEXT PROBE':<24} {'RAW':<6} {'HOOK':<6} STATUS")
    print("-" * 72)
    for label, ctx in CONTEXT_PROBES:
        exists = context_exists(ctx)
        hides = hook_would_hide_context(ctx)
        st = status_of(exists, hides)
        print(f"{label:<24} {('yes' if exists else 'no'):<6} "
              f"{('hide' if hides else '-'):<6} {st}")
        if exists and not hides:
            leaks.append(("context", label, ctx))

    # --- access-check probes ---
    print()
    print(f"{'ACCESS PROBE':<28} {'RAW':<6} {'HOOK':<6} STATUS")
    print("-" * 72)
    for probes, tag in [(ACCESS_PROBES, "v2.2"), (FUTURE_PROBES, "future")]:
        for label, scon, tcon, tclass, perm in probes:
            exists = check_selinux_access(scon, tcon, tclass, perm)
            hk = hook_would_hide(scon, tcon, tclass, perm)
            st = status_of(exists, hk)
            full = f"{tag}: {label}"
            print(f"{full:<28} {('yes' if exists else 'no'):<6} "
                  f"{('hide' if hk else '-'):<6} {st}")
            if exists and not hk:
                leaks.append(("access", full,
                              f"{scon} -> {tcon} [{tclass}:{perm}]"))

    # --- status counters ---
    print()
    print("Status counters:")
    print("-" * 72)

    if new_kernel:
        exp_seq, exp_pload = 4, 1
    else:
        exp_seq, exp_pload = 0, 0

    status = read_status()
    if status:
        version, sequence, enforcing, policyload, deny_unknown = status
        seq_clean = sequence == exp_seq
        pload_clean = policyload == exp_pload

        print(f"  version={version}  enforcing={enforcing}  "
              f"deny_unknown={deny_unknown}")
        print(f"  sequence    = {sequence:>4}  expect {exp_seq:>4}  "
              f"hook -> {exp_seq}  "
              f"{color('clean', 'green') if seq_clean else color('DIRTY (hooked)', 'yellow')}")
        print(f"  policyload  = {policyload:>4}  expect {exp_pload:>4}  "
              f"hook -> {exp_pload}  "
              f"{color('clean', 'green') if pload_clean else color('DIRTY (hooked)', 'yellow')}")

        if not seq_clean or not pload_clean:
            print(f"  -> bypass patches these to sequence={exp_seq} "
                  f"policyload={exp_pload}")
    else:
        print("  (cannot read /sys/fs/selinux/status)")

    avd_seqno = read_avd_seqno()
    if avd_seqno is not None:
        seqno_clean = avd_seqno == 1
        print(f"  avdSeqNo    = {avd_seqno:>4}  expect    1  "
              f"hook -> 1  "
              f"{color('clean', 'green') if seqno_clean else color('DIRTY (hooked)', 'yellow')}")
        if not seqno_clean:
            print("  -> bypass patches avdSeqNo to 1")
    else:
        print("  (cannot read avdSeqNo)")

    # --- policy binary scan ---
    print()
    print("Policy binary scan:")
    print("-" * 72)
    sus = scan_policy_types()
    if sus is None:
        print("  (cannot read policy — rerun with: su -c 'python3 tools/audit.py')")
    elif not sus:
        print("  no framework-injected types found")
    else:
        for name in sus:
            covered = any(s.strip(":") in name for s in HOOK_BLOCKLIST)
            marker = color("hidden", "green") if covered else color("EXPOSED", "red")
            print(f"  {name:<40} {marker}")
            if not covered:
                leaks.append(("type", name, "not in blocklist"))

    # --- summary ---
    print()
    print("=" * 72)
    if leaks:
        print(f"{color('LEAKS', 'red')}: {len(leaks)} issue(s) a detector could exploit")
        print()
        for kind, label, detail in leaks:
            print(f"  [{kind}] {label}")
            print(f"         {detail}")
        print()
        print("Fix: add missing patterns to kHidden[]/kHiddenExact[] in")
        print("jni/module.cpp and HOOK_BLOCKLIST/HOOK_EXACT_PROBES here.")
    else:
        print(color("No leaks. DirtySepolicy should report:", "green"))
        print(f"  OK: no dirty sepolicy found")
        print(f"  INFO: sequence={exp_seq} policyload={exp_pload}")

    print()
    print("Note: this runs without Zygisk hooks (raw kernel state).")
    print("Status counters marked DIRTY are expected — the bypass module")
    print("patches them at read time inside app_zygote. Run the")
    print("DirtySepolicy app to verify the hooks are live.")


if __name__ == "__main__":
    main()
