// DirtySepolicy Bypass — Zygisk module (v5.0.2-targeted)
// Defeats DirtySepolicy v2.0-v2.2 AND DuckDetector dirty sepolicy detection.
// Uses manual GOT patching (SuKiSu/KernelSU compatible) with Zygisk pltHookCommit fallback.
// v5.0.2: install only in DuckDetector/DirtySepolicy target processes. Unblock
//     hidden-context writes so the read hook patches responses instead of
//     returning EINVAL to the carrier.

#include <string.h>
#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdarg.h>
#include <unistd.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <elf.h>
#include <link.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/sysmacros.h>
#include <sys/utsname.h>

#include <android/log.h>
#include "zygisk.hpp"

#define LOG_TAG "DirtySepBypass"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO,  LOG_TAG, __VA_ARGS__)
#define LOGW(...) __android_log_print(ANDROID_LOG_WARN,  LOG_TAG, __VA_ARGS__)
#ifdef DEBUG
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)
#else
#define LOGD(...) ((void)0)
#endif

void *operator new   (size_t s)              { return malloc(s); }
void *operator new[] (size_t s)              { return malloc(s); }
void  operator delete   (void *p) noexcept   { free(p); }
void  operator delete[] (void *p) noexcept   { free(p); }
void  operator delete   (void *p, size_t) noexcept { free(p); }
void  operator delete[] (void *p, size_t) noexcept { free(p); }

// ---- hidden context substrings ------------------------------------------

static const char *const kHidden[] = {
    ":magisk",     ":kitsune",    ":apatch",
    ":ksu",        ":kernelsu",
    ":lsposed",    ":xposed",     ":riru",
    ":adbroot",
    ":supersu",    ":supolicy",   ":su:",
    ":zygisk",
    nullptr,
};

static inline bool is_hidden(const char *con) {
    if (!con) return false;
    for (int i = 0; kHidden[i]; ++i) {
        if (strstr(con, kHidden[i])) return true;
    }
    return false;
}

// ---- exact-match probes (stock contexts, framework-injected rules) ------

struct ExactProbe {
    const char *scon;
    const char *tcon;
    const char *tclass;
    const char *perm;
};

static const ExactProbe kHiddenExact[] = {
    {"u:object_r:rootfs:s0", "u:object_r:tmpfs:s0", "filesystem", "associate"},
    {"u:r:kernel:s0",        "u:object_r:tmpfs:s0", "fifo_file",  "open"},
    {"u:r:kernel:s0",        "u:object_r:adb_data_file:s0", "file", "read"},
    {"u:r:system_server:s0", "u:object_r:apk_data_file:s0", "file", "execute"},
    {"u:r:dex2oat:s0",       "u:object_r:dex2oat_exec:s0",  "file", "execute_no_trans"},
    {"u:r:zygote:s0",        "u:object_r:adb_data_file:s0", "dir",  "search"},
    {"u:r:shell:s0",         "u:r:su:s0",                   "process", "transition"},
    {"u:r:system_server:s0", "u:r:system_server:s0",        "process", "execmem"},
    {"u:r:msd_app:s0",       "u:r:msd_daemon:s0",           "unix_stream_socket", "connectto"},
    {"u:r:msd_daemon:s0",    "u:r:msd_daemon:s0",           "unix_stream_socket", "connectto"},
    {"u:r:msd_daemon:s0",    "u:object_r:selinuxfs:s0",     "file", "read"},
    {"u:r:msd_daemon:s0",    "u:object_r:configfs:s0",      "dir",  "search"},
    {"u:r:msd_daemon:s0",    "u:object_r:configfs:s0",      "file", "write"},
    {"u:r:su:s0",            "u:r:droidspacesd:s0",         "process", "transition"},
    {"u:r:magisk:s0",        "u:r:droidspacesd:s0",         "process", "transition"},
    {"u:r:system_server:s0", "u:r:droidspacesd:s0",         "binder",  "call"},
    {"u:r:fsck:s0",          "u:r:fsck:s0",                 "capability", "sys_admin"},
    {"u:r:adbd:s0",          "u:r:adbroot:s0",              "binder", "call"},
    {nullptr, nullptr, nullptr, nullptr},
};

static inline bool is_hidden_exact(const char *scon, const char *tcon,
                                   const char *tclass, const char *perm) {
    if (!scon || !tcon || !tclass || !perm) return false;
    for (int i = 0; kHiddenExact[i].scon; ++i) {
        if (strcmp(scon, kHiddenExact[i].scon) == 0 &&
            strcmp(tcon, kHiddenExact[i].tcon) == 0 &&
            strcmp(tclass, kHiddenExact[i].tclass) == 0 &&
            strcmp(perm, kHiddenExact[i].perm) == 0) {
            return true;
        }
    }
    return false;
}

// ---- hidden class:perm pairs (broad perm hiding) -------------------------

struct ClassPerm { const char *cls; const char *perm; };
static const ClassPerm kHiddenClassPerms[] = {
    { "process", "execmem" },
    { nullptr, nullptr },
};

static inline bool is_hidden_perm(const char *perm) {
    if (!perm) return false;
    for (int i = 0; kHiddenClassPerms[i].perm; ++i) {
        if (strcmp(perm, kHiddenClassPerms[i].perm) == 0) return true;
    }
    return false;
}

// ---- numeric resolution via sysfs ----------------------------------------

typedef unsigned int   access_vector_t;
typedef unsigned short security_class_t;

struct ResolvedBit {
    security_class_t cls_id;
    access_vector_t  perm_bit;
};
static ResolvedBit g_hidden_bits[8] = {};
static int         g_hidden_bit_count = 0;

struct ExactBit {
    const char      *scon;
    const char      *tcon;
    security_class_t cls_id;
    access_vector_t  perm_bit;
};
static ExactBit g_exact_bits[32] = {};
static int      g_exact_bit_count = 0;

static bool g_bits_resolved = false;

static bool read_int_file(const char *path, int *out) {
    FILE *f = fopen(path, "re");
    if (!f) { LOGD("read_int_file: fopen(%s) failed: %s", path, strerror(errno)); return false; }
    char buf[32];
    bool ok = fgets(buf, sizeof(buf), f) != nullptr;
    fclose(f);
    if (!ok) { LOGD("read_int_file: fgets(%s) returned null", path); return false; }
    *out = atoi(buf);
    return true;
}

static bool resolve_class_perm(const char *cls, const char *perm,
                                security_class_t *out_cls, access_vector_t *out_bit) {
    char path[256];
    int cid, pid;
    snprintf(path, sizeof(path), "/sys/fs/selinux/class/%s/index", cls);
    if (!read_int_file(path, &cid)) { LOGD("resolve_class_perm: unavailable %s:%s (class index)", cls, perm); return false; }
    snprintf(path, sizeof(path), "/sys/fs/selinux/class/%s/perms/%s", cls, perm);
    if (!read_int_file(path, &pid)) { LOGD("resolve_class_perm: unavailable %s:%s (perm bit)", cls, perm); return false; }
    *out_cls = (security_class_t)cid;
    *out_bit = 1u << (pid - 1);
    LOGD("resolved %s:%s -> class=%u bit=0x%x", cls, perm, cid, *out_bit);
    return true;
}

static void resolve_hidden_bits() {
    if (g_bits_resolved) return;

    for (int i = 0; kHiddenClassPerms[i].cls && g_hidden_bit_count < 8; ++i) {
        security_class_t cid;
        access_vector_t pbit;
        if (resolve_class_perm(kHiddenClassPerms[i].cls, kHiddenClassPerms[i].perm,
                               &cid, &pbit)) {
            g_hidden_bits[g_hidden_bit_count++] = { cid, pbit };
        }
    }
    for (int i = 0; kHiddenExact[i].scon && g_exact_bit_count < 32; ++i) {
        security_class_t cid;
        access_vector_t pbit;
        if (resolve_class_perm(kHiddenExact[i].tclass, kHiddenExact[i].perm,
                               &cid, &pbit)) {
            g_exact_bits[g_exact_bit_count++] = {
                kHiddenExact[i].scon, kHiddenExact[i].tcon, cid, pbit
            };
        }
    }

    g_bits_resolved = true;
    LOGD("resolve_hidden_bits: %d broad, %d exact", g_hidden_bit_count, g_exact_bit_count);
}

// ---- kernel version detection -------------------------------------------

static bool g_new_kernel = false;

static void detect_kernel_version() {
    struct utsname uts;
    if (uname(&uts) != 0) { LOGW("detect_kernel_version: uname() failed: %s", strerror(errno)); return; }
    int major = 0, minor = 0;
    sscanf(uts.release, "%d.%d", &major, &minor);
    g_new_kernel = (major > 6 || (major == 6 && minor >= 10));
    LOGD("kernel %s -> %d.%d, new_kernel=%d", uts.release, major, minor, g_new_kernel);
}

// ---- fd tracking --------------------------------------------------------

enum FdType : unsigned char {
    FD_NONE = 0,
    FD_CONTEXT,
    FD_ACCESS,
    FD_STATUS,
};

struct TrackedFd {
    int fd;
    FdType type;
    char scon[256];
    char tcon[256];
    unsigned int tclass;
    bool has_query;
};

#define MAX_TRACKED 16
static TrackedFd g_tracked[MAX_TRACKED];
static int g_tracked_count = 0;

static TrackedFd *find_tracked(int fd) {
    for (int i = 0; i < g_tracked_count; ++i)
        if (g_tracked[i].fd == fd) return &g_tracked[i];
    return nullptr;
}

static void track_fd(int fd, FdType type) {
    for (int i = 0; i < g_tracked_count; ++i) {
        if (g_tracked[i].fd == fd) {
            g_tracked[i].type = type;
            g_tracked[i].scon[0] = '\0';
            g_tracked[i].tcon[0] = '\0';
            g_tracked[i].tclass = 0;
            g_tracked[i].has_query = false;
            return;
        }
    }
    if (g_tracked_count >= MAX_TRACKED) { LOGW("track_fd: MAX_TRACKED (%d) exceeded, dropping fd %d", MAX_TRACKED, fd); return; }
    auto *t = &g_tracked[g_tracked_count++];
    t->fd = fd;
    t->type = type;
    t->scon[0] = '\0';
    t->tcon[0] = '\0';
    t->tclass = 0;
    t->has_query = false;
}

static void untrack_fd(int fd) {
    for (int i = 0; i < g_tracked_count; ++i) {
        if (g_tracked[i].fd == fd) {
            g_tracked[i] = g_tracked[--g_tracked_count];
            return;
        }
    }
}

static const char *selinuxfs_name(const char *path) {
    if (strncmp(path, "/sys/fs/selinux/", 16) == 0) return path + 16;
    if (strncmp(path, "/selinux/", 9) == 0)         return path + 9;
    return nullptr;
}

static FdType classify_path(const char *path) {
    if (!path) return FD_NONE;
    const char *name = selinuxfs_name(path);
    if (name) {
        if (strcmp(name, "access") == 0)  return FD_ACCESS;
        if (strcmp(name, "status") == 0)  return FD_STATUS;
        if (strcmp(name, "context") == 0 ||
            strcmp(name, "create") == 0 ||
            strcmp(name, "member") == 0 ||
            strcmp(name, "relabel") == 0 ||
            strcmp(name, "user") == 0 ||
            strcmp(name, "validatetrans") == 0) return FD_CONTEXT;
    }
    if (strncmp(path, "/proc/", 6) == 0 && strstr(path, "/attr/"))
        return FD_CONTEXT;
    return FD_NONE;
}

// ---- access query parsing and response patching -------------------------

static void parse_access_query(TrackedFd *tfd, const char *query) {
    const char *sp1 = strchr(query, ' ');
    if (!sp1) { LOGW("parse_access_query: no first space in '%s'", query); return; }
    size_t len = sp1 - query;
    if (len >= sizeof(tfd->scon)) len = sizeof(tfd->scon) - 1;
    memcpy(tfd->scon, query, len);
    tfd->scon[len] = '\0';

    const char *p = sp1 + 1;
    const char *sp2 = strchr(p, ' ');
    if (!sp2) { LOGW("parse_access_query: no second space in '%s'", query); return; }
    len = sp2 - p;
    if (len >= sizeof(tfd->tcon)) len = sizeof(tfd->tcon) - 1;
    memcpy(tfd->tcon, p, len);
    tfd->tcon[len] = '\0';

    tfd->tclass = (unsigned int)strtoul(sp2 + 1, nullptr, 10);
    tfd->has_query = true;
    LOGD("access query: scon=%s tcon=%s class=%u", tfd->scon, tfd->tcon, tfd->tclass);
}

static ssize_t patch_access_response(TrackedFd *tfd, char *buf,
                                     ssize_t ret, size_t bufsize) {
    if (ret <= 0 || (size_t)ret >= bufsize) return ret;
    char tmp[128];
    if ((size_t)ret >= sizeof(tmp)) return ret;
    memcpy(tmp, buf, ret);
    tmp[ret] = '\0';

    unsigned int allowed, decided, auditallow, auditdeny, flags, seqno;
    if (sscanf(tmp, "%x %x %x %x %u %x",
               &allowed, &decided, &auditallow, &auditdeny, &seqno, &flags) != 6) {
        LOGW("patch_access_response: sscanf failed on '%s'", tmp);
        return ret;
    }

    unsigned int orig_allowed = allowed, orig_auditallow = auditallow;

    for (int i = 0; i < g_hidden_bit_count; ++i) {
        if (g_hidden_bits[i].cls_id == (security_class_t)tfd->tclass) {
            allowed    &= ~g_hidden_bits[i].perm_bit;
            auditallow &= ~g_hidden_bits[i].perm_bit;
        }
    }
    for (int i = 0; i < g_exact_bit_count; ++i) {
        if (g_exact_bits[i].cls_id == (security_class_t)tfd->tclass &&
            strcmp(tfd->scon, g_exact_bits[i].scon) == 0 &&
            strcmp(tfd->tcon, g_exact_bits[i].tcon) == 0) {
            allowed    &= ~g_exact_bits[i].perm_bit;
            auditallow &= ~g_exact_bits[i].perm_bit;
        }
    }

    unsigned int orig_seqno = seqno;
    seqno = 1;

    if (allowed != orig_allowed || auditallow != orig_auditallow || orig_seqno != 1)
        LOGD("patch_access: scon=%s tcon=%s class=%u allowed=0x%x->0x%x",
             tfd->scon, tfd->tcon, tfd->tclass, orig_allowed, allowed);

    int newlen = snprintf(buf, bufsize, "%x %x %x %x %u %x",
                          allowed, decided, auditallow, auditdeny, seqno, flags);
    if (newlen < 0 || (size_t)newlen >= bufsize) return ret;
    return newlen;
}

// ---- status patching ----------------------------------------------------

static void patch_status(void *buf, ssize_t len) {
    if (len < 20) { LOGW("patch_status: buffer too short (%zd < 20)", len); return; }
    auto *p = (unsigned char *)buf;
    unsigned int seq, pload;
    if (g_new_kernel) {
        seq = 4;  pload = 1;
    } else {
        seq = 0;  pload = 0;
    }
#ifdef DEBUG
    unsigned int raw_seq, raw_pload;
    memcpy(&raw_seq, p + 4, sizeof(raw_seq));
    memcpy(&raw_pload, p + 12, sizeof(raw_pload));
    LOGD("patch_status: seq=%u->%u policyload=%u->%u", raw_seq, seq, raw_pload, pload);
#endif
    memcpy(p + 4,  &seq,   sizeof(seq));
    memcpy(p + 12, &pload, sizeof(pload));
}

// ---- libselinux ABI (defense-in-depth hooks) ----------------------------

struct av_decision {
    access_vector_t allowed;
    access_vector_t decided;
    access_vector_t auditallow;
    access_vector_t auditdeny;
    unsigned int    seqno;
    unsigned int    flags;
};

static inline void mask_hidden_bits(security_class_t tclass, av_decision *avd) {
    if (!avd) return;
    for (int i = 0; i < g_hidden_bit_count; ++i) {
        if (g_hidden_bits[i].cls_id == tclass) {
            avd->allowed    &= ~g_hidden_bits[i].perm_bit;
            avd->auditallow &= ~g_hidden_bits[i].perm_bit;
        }
    }
}

static inline void mask_exact_bits(const char *scon, const char *tcon,
                                   security_class_t tclass, av_decision *avd) {
    if (!avd || !scon || !tcon) return;
    for (int i = 0; i < g_exact_bit_count; ++i) {
        if (g_exact_bits[i].cls_id == tclass &&
            strcmp(scon, g_exact_bits[i].scon) == 0 &&
            strcmp(tcon, g_exact_bits[i].tcon) == 0) {
            avd->allowed    &= ~g_exact_bits[i].perm_bit;
            avd->auditallow &= ~g_exact_bits[i].perm_bit;
        }
    }
}

static void fake_deny(av_decision *avd) {
    if (!avd) return;
    avd->allowed    = 0;
    avd->decided    = ~0u;
    avd->auditallow = 0;
    avd->auditdeny  = ~0u;
    avd->seqno      = 1;
    avd->flags      = 0;
}

static int (*orig_security_compute_av)(const char *, const char *,
                                       security_class_t, access_vector_t,
                                       av_decision *) = nullptr;
static int (*orig_security_compute_av_flags)(const char *, const char *,
                                             security_class_t, access_vector_t,
                                             av_decision *) = nullptr;
static int (*orig_selinux_check_access)(const char *, const char *,
                                        const char *, const char *,
                                        void *) = nullptr;

static int my_security_compute_av(const char *scon, const char *tcon,
                                  security_class_t tclass,
                                  access_vector_t requested,
                                  av_decision *avd) {
    if (is_hidden(scon) || is_hidden(tcon)) {
        LOGD("compute_av: fake deny for hidden scon=%s tcon=%s", scon ? scon : "(null)", tcon ? tcon : "(null)");
        fake_deny(avd);
        return 0;
    }
    if (!orig_security_compute_av) { LOGW("compute_av: orig is null"); errno = ENOSYS; return -1; }
    int r = orig_security_compute_av(scon, tcon, tclass, requested, avd);
    if (r == 0) {
        unsigned int pre = avd ? avd->allowed : 0;
        mask_hidden_bits(tclass, avd);
        mask_exact_bits(scon, tcon, tclass, avd);
        if (avd) {
            if (avd->allowed != pre)
                LOGD("compute_av: masked scon=%s tcon=%s class=%u allowed=0x%x->0x%x", scon, tcon, tclass, pre, avd->allowed);
            avd->seqno = 1;
        }
    }
    return r;
}

static int my_security_compute_av_flags(const char *scon, const char *tcon,
                                        security_class_t tclass,
                                        access_vector_t requested,
                                        av_decision *avd) {
    if (is_hidden(scon) || is_hidden(tcon)) {
        LOGD("compute_av_flags: fake deny for hidden scon=%s tcon=%s", scon ? scon : "(null)", tcon ? tcon : "(null)");
        fake_deny(avd);
        return 0;
    }
    if (!orig_security_compute_av_flags) { LOGW("compute_av_flags: orig is null"); errno = ENOSYS; return -1; }
    int r = orig_security_compute_av_flags(scon, tcon, tclass, requested, avd);
    if (r == 0) {
        unsigned int pre = avd ? avd->allowed : 0;
        mask_hidden_bits(tclass, avd);
        mask_exact_bits(scon, tcon, tclass, avd);
        if (avd) {
            if (avd->allowed != pre)
                LOGD("compute_av_flags: masked scon=%s tcon=%s class=%u allowed=0x%x->0x%x", scon, tcon, tclass, pre, avd->allowed);
            avd->seqno = 1;
        }
    }
    return r;
}

static int my_selinux_check_access(const char *scon, const char *tcon,
                                   const char *tclass, const char *perm,
                                   void *auditdata) {
    if (is_hidden(scon) || is_hidden(tcon) || is_hidden_perm(perm) ||
        is_hidden_exact(scon, tcon, tclass, perm)) {
        LOGD("check_access: denied %s -> %s [%s:%s]", scon ? scon : "(null)", tcon ? tcon : "(null)", tclass ? tclass : "(null)", perm ? perm : "(null)");
        errno = EACCES;
        return -1;
    }
    if (orig_selinux_check_access)
        return orig_selinux_check_access(scon, tcon, tclass, perm, auditdata);
    LOGW("check_access: orig is null");
    errno = ENOSYS;
    return -1;
}

// ---- file I/O hooks -----------------------------------------------------

static int     (*orig_open)(const char *, int, ...) = nullptr;
static int     (*orig___open_2)(const char *, int) = nullptr;
static int     (*orig_openat)(int, const char *, int, ...) = nullptr;
static int     (*orig___openat_2)(int, const char *, int) = nullptr;
static ssize_t (*orig_write)(int, const void *, size_t) = nullptr;
static ssize_t (*orig___write_chk)(int, const void *, size_t, size_t) = nullptr;
static ssize_t (*orig_read)(int, void *, size_t) = nullptr;
static ssize_t (*orig___read_chk)(int, void *, size_t, size_t) = nullptr;
static ssize_t (*orig_pread)(int, void *, size_t, off_t) = nullptr;
static ssize_t (*orig_pread64)(int, void *, size_t, off64_t) = nullptr;
static ssize_t (*orig___pread_chk)(int, void *, size_t, off_t, size_t) = nullptr;
static int     (*orig_close)(int) = nullptr;
static void   *(*orig_mmap)(void *, size_t, int, int, int, off_t) = nullptr;
static int     (*orig_munmap)(void *, size_t) = nullptr;
static FILE   *(*orig_fopen)(const char *, const char *) = nullptr;
static size_t  (*orig_fread)(void *, size_t, size_t, FILE *) = nullptr;
static size_t  (*orig_fwrite)(const void *, size_t, size_t, FILE *) = nullptr;
static int     (*orig_fclose)(FILE *) = nullptr;
static long    (*orig_syscall)(long, ...) = nullptr;
static void   *(*orig_dlopen)(const char *, int) = nullptr;
static void   *(*orig_android_dlopen_ext)(const char *, int, const void *) = nullptr;
static void   *(*orig_dlsym)(void *, const char *) = nullptr;

static int manual_hook_libs();

#ifdef DEBUG
static const char *fdtype_str(FdType t) {
    switch (t) {
        case FD_CONTEXT: return "context";
        case FD_ACCESS:  return "access";
        case FD_STATUS:  return "status";
        default:         return "none";
    }
}
#endif

static void maybe_track_path(int fd, const char *path, const char *api_name) {
    (void)api_name;
    if (fd < 0) return;
    FdType type = classify_path(path);
    if (type != FD_NONE) {
        track_fd(fd, type);
        LOGD("%s: tracking fd=%d type=%s path=%s", api_name, fd, fdtype_str(type), path ? path : "(null)");
    }
}

static int my_open(const char *pathname, int flags, mode_t mode) {
    int fd = orig_open ? orig_open(pathname, flags, mode) : -1;
    maybe_track_path(fd, pathname, "open");
    return fd;
}

static int my___open_2(const char *pathname, int flags) {
    int fd = orig___open_2 ? orig___open_2(pathname, flags)
                           : (orig_open ? orig_open(pathname, flags, 0) : -1);
    maybe_track_path(fd, pathname, "__open_2");
    return fd;
}

static int my_openat(int dirfd, const char *pathname, int flags, mode_t mode) {
    int fd = orig_openat ? orig_openat(dirfd, pathname, flags, mode) : -1;
    maybe_track_path(fd, pathname, "openat");
    return fd;
}

static int my___openat_2(int dirfd, const char *pathname, int flags) {
    int fd = orig___openat_2 ? orig___openat_2(dirfd, pathname, flags)
                             : (orig_openat ? orig_openat(dirfd, pathname, flags, 0) : -1);
    maybe_track_path(fd, pathname, "__openat_2");
    return fd;
}

static bool process_tracked_write(int fd, const void *buf, size_t count) {
    if (g_tracked_count > 0 && buf && count > 0 && count < 512) {
        auto *tfd = find_tracked(fd);
        if (tfd) {
            char tmp[512];
            memcpy(tmp, buf, count);
            tmp[count] = '\0';
            // Parse the query for ALL access writes (hidden or not).
            // We no longer block hidden-context writes — instead we let
            // the kernel process the query and patch the response in the
            // read hook.  This avoids returning -1/EINVAL to the carrier
            // process, which would look like an error rather than a clean
            // "denied" result.
            if (tfd->type == FD_ACCESS)
                parse_access_query(tfd, tmp);
        }
    }
    return true;
}

static ssize_t my_write(int fd, const void *buf, size_t count) {
    if (!process_tracked_write(fd, buf, count)) return -1;
    if (!orig_write) { errno = ENOSYS; return -1; }
    return orig_write(fd, buf, count);
}

static ssize_t my___write_chk(int fd, const void *buf, size_t count, size_t bufsize) {
    if (!process_tracked_write(fd, buf, count)) return -1;
    if (orig___write_chk) return orig___write_chk(fd, buf, count, bufsize);
    if (orig_write) return orig_write(fd, buf, count);
    errno = ENOSYS;
    return -1;
}

static ssize_t patch_fd_read(int fd, void *buf, ssize_t ret, size_t count) {
    if (ret <= 0 || g_tracked_count == 0) return ret;
    auto *tfd = find_tracked(fd);
    if (!tfd) return ret;
    if (tfd->type == FD_ACCESS && tfd->has_query) {
        ret = patch_access_response(tfd, (char *)buf, ret, count);
        tfd->has_query = false;
    } else if (tfd->type == FD_STATUS) {
        patch_status(buf, ret);
    }
    return ret;
}

static ssize_t my_read(int fd, void *buf, size_t count) {
    if (!orig_read) { errno = ENOSYS; return -1; }
    ssize_t ret = orig_read(fd, buf, count);
    return patch_fd_read(fd, buf, ret, count);
}

static ssize_t my___read_chk(int fd, void *buf, size_t count, size_t bufsize) {
    ssize_t ret;
    if (orig___read_chk) ret = orig___read_chk(fd, buf, count, bufsize);
    else if (orig_read) ret = orig_read(fd, buf, count);
    else { errno = ENOSYS; return -1; }
    return patch_fd_read(fd, buf, ret, count);
}

static ssize_t my_pread(int fd, void *buf, size_t count, off_t offset) {
    if (!orig_pread) { errno = ENOSYS; return -1; }
    ssize_t ret = orig_pread(fd, buf, count, offset);
    return patch_fd_read(fd, buf, ret, count);
}

static ssize_t my_pread64(int fd, void *buf, size_t count, off64_t offset) {
    ssize_t ret;
    if (orig_pread64) ret = orig_pread64(fd, buf, count, offset);
    else if (orig_pread) ret = orig_pread(fd, buf, count, (off_t)offset);
    else { errno = ENOSYS; return -1; }
    return patch_fd_read(fd, buf, ret, count);
}

static ssize_t my___pread_chk(int fd, void *buf, size_t count, off_t offset, size_t bufsize) {
    ssize_t ret;
    if (orig___pread_chk) ret = orig___pread_chk(fd, buf, count, offset, bufsize);
    else if (orig_pread) ret = orig_pread(fd, buf, count, offset);
    else if (orig_pread64) ret = orig_pread64(fd, buf, count, (off64_t)offset);
    else { errno = ENOSYS; return -1; }
    return patch_fd_read(fd, buf, ret, count);
}

static int my_close(int fd) {
    if (g_tracked_count > 0)
        untrack_fd(fd);
    return orig_close ? orig_close(fd) : -1;
}

static void *my_mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset) {
    auto *tfd = find_tracked(fd);
    if (tfd && tfd->type == FD_STATUS && offset == 0 && length >= 20 && !(flags & MAP_FIXED)) {
        if (!orig_mmap) { errno = ENOSYS; return MAP_FAILED; }
        void *map = orig_mmap(addr, length, PROT_READ | PROT_WRITE,
                              MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (map != MAP_FAILED) {
            ssize_t n = -1;
            if (orig_pread) n = orig_pread(fd, map, length, 0);
            else if (orig_pread64) n = orig_pread64(fd, map, length, 0);
            else if (orig_read) n = orig_read(fd, map, length);
            if (n >= 20) patch_status(map, n);
            if (!(prot & PROT_WRITE))
                mprotect(map, length, prot);
            LOGD("mmap: returned patched status mapping len=%zu", length);
            return map;
        }
    }
    if (!orig_mmap) { errno = ENOSYS; return MAP_FAILED; }
    return orig_mmap(addr, length, prot, flags, fd, offset);
}

static int my_munmap(void *addr, size_t length) {
    return orig_munmap ? orig_munmap(addr, length) : -1;
}

static FILE *my_fopen(const char *path, const char *mode) {
    FILE *f = orig_fopen ? orig_fopen(path, mode) : nullptr;
    if (f) maybe_track_path(fileno(f), path, "fopen");
    return f;
}

static size_t my_fread(void *ptr, size_t size, size_t nmemb, FILE *stream) {
    if (!orig_fread) { errno = ENOSYS; return 0; }
    size_t ret = orig_fread(ptr, size, nmemb, stream);
    if (ret && size && stream) {
        int fd = fileno(stream);
        size_t bytes = ret * size;
        (void)patch_fd_read(fd, ptr, (ssize_t)bytes, bytes);
    }
    return ret;
}

static size_t my_fwrite(const void *ptr, size_t size, size_t nmemb, FILE *stream) {
    size_t bytes = size * nmemb;
    if (stream && !process_tracked_write(fileno(stream), ptr, bytes))
        return 0;
    if (!orig_fwrite) { errno = ENOSYS; return 0; }
    return orig_fwrite(ptr, size, nmemb, stream);
}

static int my_fclose(FILE *stream) {
    if (stream && g_tracked_count > 0)
        untrack_fd(fileno(stream));
    return orig_fclose ? orig_fclose(stream) : -1;
}

static long my_syscall(long number, ...) {
    va_list ap;
    va_start(ap, number);
    long a1 = va_arg(ap, long);
    long a2 = va_arg(ap, long);
    long a3 = va_arg(ap, long);
    long a4 = va_arg(ap, long);
    long a5 = va_arg(ap, long);
    long a6 = va_arg(ap, long);
    va_end(ap);

    switch (number) {
#ifdef __NR_open
        case __NR_open:
            return my_open((const char *)a1, (int)a2, (mode_t)a3);
#endif
#ifdef __NR_openat
        case __NR_openat:
            return my_openat((int)a1, (const char *)a2, (int)a3, (mode_t)a4);
#endif
#ifdef __NR_read
        case __NR_read:
            return my_read((int)a1, (void *)a2, (size_t)a3);
#endif
#ifdef __NR_write
        case __NR_write:
            return my_write((int)a1, (const void *)a2, (size_t)a3);
#endif
#ifdef __NR_pread64
        case __NR_pread64:
            return my_pread64((int)a1, (void *)a2, (size_t)a3, (off64_t)a4);
#endif
#ifdef __NR_close
        case __NR_close:
            return my_close((int)a1);
#endif
#ifdef __NR_mmap
        case __NR_mmap:
            return (long)my_mmap((void *)a1, (size_t)a2, (int)a3, (int)a4, (int)a5, (off_t)a6);
#endif
#ifdef __NR_mmap2
        case __NR_mmap2:
            return (long)my_mmap((void *)a1, (size_t)a2, (int)a3, (int)a4, (int)a5, (off_t)(a6 << 12));
#endif
        default:
            if (!orig_syscall) { errno = ENOSYS; return -1; }
            return orig_syscall(number, a1, a2, a3, a4, a5, a6);
    }
}

static void *my_dlsym(void *handle, const char *symbol) {
    if (symbol) {
        if (strcmp(symbol, "security_compute_av") == 0)
            return (void *)my_security_compute_av;
        if (strcmp(symbol, "security_compute_av_flags") == 0)
            return (void *)my_security_compute_av_flags;
        if (strcmp(symbol, "selinux_check_access") == 0)
            return (void *)my_selinux_check_access;
    }
    if (!orig_dlsym) { errno = ENOSYS; return nullptr; }
    return orig_dlsym(handle, symbol);
}

static void rehook_after_load(const char *path) {
    (void)path;
    static bool in_rehook = false;
    if (in_rehook) return;
    in_rehook = true;
    int n = manual_hook_libs();
    (void)n;
    LOGD("dlopen: rehooked %d libs after %s", n, path ? path : "(null)");
    in_rehook = false;
}

static void *my_dlopen(const char *filename, int flags) {
    if (!orig_dlopen) { errno = ENOSYS; return nullptr; }
    void *h = orig_dlopen(filename, flags);
    if (h) rehook_after_load(filename);
    return h;
}

static void *my_android_dlopen_ext(const char *filename, int flags, const void *extinfo) {
    if (!orig_android_dlopen_ext) {
        if (orig_dlopen)
            return my_dlopen(filename, flags);
        errno = ENOSYS;
        return nullptr;
    }
    void *h = orig_android_dlopen_ext(filename, flags, extinfo);
    if (h) rehook_after_load(filename);
    return h;
}

// ---- JNI payload sanitizer (covers detector raw-syscall backends) ---------

static jstring (*orig_NewStringUTF)(JNIEnv *, const char *) = nullptr;
static bool g_jni_hooked = false;

static char *sanitize_payload(const char *utf) {
    if (!utf) return nullptr;
    if (!strstr(utf, "DIRTY_POLICY_") && !strstr(utf, "JAVA_DIRTY_POLICY_"))
        return nullptr;

    char *copy = strdup(utf);
    if (!copy) return nullptr;

    bool changed = false;
    const char needle[] = "_ALLOWED=1";
    const size_t needle_len = sizeof(needle) - 1;
    for (char *p = strstr(copy, needle); p; p = strstr(p + needle_len, needle)) {
        char *line = p;
        while (line > copy && line[-1] != '\n') --line;
        if (strncmp(line, "DIRTY_POLICY_", 13) == 0 ||
            strncmp(line, "JAVA_DIRTY_POLICY_", 18) == 0) {
            p[needle_len - 1] = '0';
            changed = true;
        }
    }

    if (!changed) {
        free(copy);
        return nullptr;
    }
    return copy;
}

static jstring my_NewStringUTF(JNIEnv *env, const char *utf) {
    if (!orig_NewStringUTF) return nullptr;
    char *patched = sanitize_payload(utf);
    if (patched) {
        LOGD("NewStringUTF: sanitized dirty policy payload");
        jstring out = orig_NewStringUTF(env, patched);
        free(patched);
        return out;
    }
    return orig_NewStringUTF(env, utf);
}

static void hook_jni(JNIEnv *env) {
    if (!env || g_jni_hooked) return;
    auto *table = const_cast<JNINativeInterface *>(env->functions);
    if (!table || !table->NewStringUTF || table->NewStringUTF == my_NewStringUTF)
        return;

    long page_size_long = sysconf(_SC_PAGESIZE);
    uintptr_t page_size = page_size_long > 0 ? (uintptr_t)page_size_long : (uintptr_t)4096;
    uintptr_t page = (uintptr_t)&table->NewStringUTF & ~(page_size - 1);
    if (mprotect((void *)page, page_size, PROT_READ | PROT_WRITE) != 0) {
        LOGW("hook_jni: mprotect failed: %s", strerror(errno));
        return;
    }

    orig_NewStringUTF = table->NewStringUTF;
    table->NewStringUTF = my_NewStringUTF;
    mprotect((void *)page, page_size, PROT_READ);
    g_jni_hooked = true;
    LOGI("JNI NewStringUTF hook installed");
}

// ---- manual GOT/PLT patching (bypasses pltHookCommit) -------------------

struct HookEntry {
    const char *symbol;
    void       *newFunc;
    void      **origFunc;
};

static const HookEntry g_all_hooks[] = {
    { "open",                      (void *)my_open,                      (void **)&orig_open },
    { "__open_2",                  (void *)my___open_2,                  (void **)&orig___open_2 },
    { "openat",                    (void *)my_openat,                    (void **)&orig_openat },
    { "__openat_2",                (void *)my___openat_2,                (void **)&orig___openat_2 },
    { "write",                     (void *)my_write,                     (void **)&orig_write },
    { "__write_chk",               (void *)my___write_chk,               (void **)&orig___write_chk },
    { "read",                      (void *)my_read,                      (void **)&orig_read },
    { "__read_chk",                (void *)my___read_chk,                (void **)&orig___read_chk },
    { "pread",                     (void *)my_pread,                     (void **)&orig_pread },
    { "pread64",                   (void *)my_pread64,                   (void **)&orig_pread64 },
    { "__pread_chk",               (void *)my___pread_chk,               (void **)&orig___pread_chk },
    { "close",                     (void *)my_close,                     (void **)&orig_close },
    { "mmap",                      (void *)my_mmap,                      (void **)&orig_mmap },
    { "munmap",                    (void *)my_munmap,                    (void **)&orig_munmap },
    { "fopen",                     (void *)my_fopen,                     (void **)&orig_fopen },
    { "fread",                     (void *)my_fread,                     (void **)&orig_fread },
    { "fwrite",                    (void *)my_fwrite,                    (void **)&orig_fwrite },
    { "fclose",                    (void *)my_fclose,                    (void **)&orig_fclose },
    { "syscall",                   (void *)my_syscall,                   (void **)&orig_syscall },
    { "dlopen",                    (void *)my_dlopen,                    (void **)&orig_dlopen },
    { "android_dlopen_ext",        (void *)my_android_dlopen_ext,        (void **)&orig_android_dlopen_ext },
    { "dlsym",                     (void *)my_dlsym,                     (void **)&orig_dlsym },
    { "security_compute_av",       (void *)my_security_compute_av,       (void **)&orig_security_compute_av },
    { "security_compute_av_flags", (void *)my_security_compute_av_flags, (void **)&orig_security_compute_av_flags },
    { "selinux_check_access",      (void *)my_selinux_check_access,      (void **)&orig_selinux_check_access },
    { nullptr, nullptr, nullptr },
};

static inline uintptr_t page_start(uintptr_t value, uintptr_t page_size) {
    return value & ~(page_size - 1);
}

static inline uintptr_t dyn_addr(uintptr_t load_bias, ElfW(Addr) value) {
    if (!value) return 0;
    uintptr_t ptr = (uintptr_t)value;
    return ptr < load_bias ? load_bias + ptr : ptr;
}

static inline unsigned int reloc_sym(uintptr_t info) {
#if defined(__LP64__)
    return (unsigned int)ELF64_R_SYM(info);
#else
    return (unsigned int)ELF32_R_SYM(info);
#endif
}

static inline unsigned int reloc_type(uintptr_t info) {
#if defined(__LP64__)
    return (unsigned int)ELF64_R_TYPE(info);
#else
    return (unsigned int)ELF32_R_TYPE(info);
#endif
}

static inline bool is_import_reloc(unsigned int type) {
#if defined(__aarch64__)
    return type == R_AARCH64_JUMP_SLOT || type == R_AARCH64_GLOB_DAT;
#elif defined(__arm__)
    return type == R_ARM_JUMP_SLOT || type == R_ARM_GLOB_DAT;
#elif defined(__i386__)
    return type == R_386_JMP_SLOT || type == R_386_GLOB_DAT;
#elif defined(__x86_64__)
    return type == R_X86_64_JUMP_SLOT || type == R_X86_64_GLOB_DAT;
#else
    (void)type;
    return true;
#endif
}

static bool patch_got(const ElfW(Dyn) *dynamic, uintptr_t load_bias, const HookEntry *hooks) {
    const ElfW(Sym) *symtab = nullptr;
    const char *strtab = nullptr;
    uintptr_t jmprel = 0;
    size_t pltrelsz = 0;
    size_t relaent = sizeof(ElfW(Rela));
    size_t relent = sizeof(ElfW(Rel));
    int pltrel = DT_RELA;
    for (auto *d = dynamic; d->d_tag != DT_NULL; ++d) {
        switch (d->d_tag) {
            case DT_SYMTAB:   symtab = (const ElfW(Sym) *)dyn_addr(load_bias, d->d_un.d_ptr); break;
            case DT_STRTAB:   strtab = (const char *)dyn_addr(load_bias, d->d_un.d_ptr); break;
            case DT_JMPREL:   jmprel = dyn_addr(load_bias, d->d_un.d_ptr); break;
            case DT_PLTRELSZ: pltrelsz = (size_t)d->d_un.d_val; break;
            case DT_PLTREL:   pltrel = (int)d->d_un.d_val; break;
            case DT_RELAENT:  relaent = (size_t)d->d_un.d_val; break;
            case DT_RELENT:   relent = (size_t)d->d_un.d_val; break;
        }
    }
    if (!symtab || !strtab || !jmprel || !pltrelsz) return false;

    int hooked = 0;
    long page_size_long = sysconf(_SC_PAGESIZE);
    uintptr_t page_size = page_size_long > 0 ? (uintptr_t)page_size_long : (uintptr_t)4096;

    size_t entry_size = pltrel == DT_REL ? relent : relaent;
    if (!entry_size) return false;
    size_t count = pltrelsz / entry_size;
    if (count > 4096) count = 4096;

    for (size_t i = 0; i < count; ++i) {
        uintptr_t info = 0;
        ElfW(Addr) offset = 0;
        if (pltrel == DT_REL) {
            auto *rel = (const ElfW(Rel) *)(jmprel + i * entry_size);
            info = (uintptr_t)rel->r_info;
            offset = rel->r_offset;
        } else {
            auto *rela = (const ElfW(Rela) *)(jmprel + i * entry_size);
            info = (uintptr_t)rela->r_info;
            offset = rela->r_offset;
        }

        if (!is_import_reloc(reloc_type(info))) continue;
        unsigned int sym_index = reloc_sym(info);
        const char *name = strtab + symtab[sym_index].st_name;
        if (!name || !*name) continue;

        for (const HookEntry *h = hooks; h->symbol; ++h) {
            if (strcmp(name, h->symbol) != 0) continue;

            void *orig = dlsym(RTLD_DEFAULT, h->symbol);
            if (orig && !*h->origFunc) *h->origFunc = orig;

            auto *slot = (ElfW(Addr) *)dyn_addr(load_bias, offset);
            if (!slot || *slot == (ElfW(Addr))h->newFunc) break;

            uintptr_t page = page_start((uintptr_t)slot, page_size);
            if (mprotect((void *)page, page_size, PROT_READ | PROT_WRITE) != 0) {
                LOGD("GOT mprotect failed for %s: %s", h->symbol, strerror(errno));
                break;
            }
            *slot = (ElfW(Addr))h->newFunc;
            mprotect((void *)page, page_size, PROT_READ);
            ++hooked;
            LOGD("GOT patched: %s @ rel[%zu]", h->symbol, i);
            break;
        }
    }
    return hooked > 0;
}

static bool should_consider_so(const char *path) {
    if (!path) return false;
    size_t len = strlen(path);
    if (len < 4) return false;
    if (strcmp(path + len - 3, ".so") != 0) return false;
    const char *basename = strrchr(path, '/');
    basename = basename ? basename + 1 : path;
    return strcmp(basename, "libdirtysepbypass.so") != 0;
}

static int manual_hook_libs() {
    FILE *fp = fopen("/proc/self/maps", "re");
    if (!fp) return 0;
    int n = 0;
    char line[1024];
    while (fgets(line, sizeof(line), fp)) {
        char *path = strchr(line, '/');
        if (!path) continue;
        size_t len = strlen(path);
        if (path[len - 1] == '\n') { path[len - 1] = '\0'; len--; }
        if (!should_consider_so(path)) continue;
        uintptr_t base = 0;
        uintptr_t map_offset = 0;
        char perms[5] = {};
        if (sscanf(line, "%" SCNxPTR "-%*" SCNxPTR " %4s %" SCNxPTR,
                   &base, perms, &map_offset) != 3 || !base)
            continue;
        if (map_offset != 0) continue;
        if (perms[0] != 'r') continue;
        auto *ehdr = (ElfW(Ehdr) *)base;
        if (memcmp(ehdr->e_ident, ELFMAG, SELFMAG) != 0) continue;
        if (ehdr->e_type != ET_DYN) continue;
        auto *phdr = (ElfW(Phdr) *)(base + ehdr->e_phoff);
        const ElfW(Dyn) *dynamic = nullptr;
        long page_size_long = sysconf(_SC_PAGESIZE);
        uintptr_t page_size = page_size_long > 0 ? (uintptr_t)page_size_long : (uintptr_t)4096;
        uintptr_t min_vaddr = UINTPTR_MAX;
        for (size_t i = 0; i < ehdr->e_phnum; ++i) {
            if (phdr[i].p_type == PT_LOAD && phdr[i].p_memsz != 0) {
                uintptr_t vaddr = page_start((uintptr_t)phdr[i].p_vaddr, page_size);
                if (vaddr < min_vaddr) min_vaddr = vaddr;
            }
        }
        if (min_vaddr == UINTPTR_MAX || base < min_vaddr) continue;
        uintptr_t load_bias = base - min_vaddr;
        for (size_t i = 0; i < ehdr->e_phnum; ++i) {
            if (phdr[i].p_type == PT_DYNAMIC) {
                dynamic = (const ElfW(Dyn) *)(load_bias + phdr[i].p_vaddr);
                break;
            }
        }
        if (!dynamic) continue;
        if (patch_got(dynamic, load_bias, g_all_hooks))
            ++n;
    }
    fclose(fp);
    return n;
}

// ---- map walking (legacy fallback for standard Magisk) ------------------

static int register_against_all_libs(zygisk::Api *api) {
    FILE *fp = fopen("/proc/self/maps", "re");
    if (!fp) { LOGW("fopen(/proc/self/maps) failed: %s", strerror(errno)); return 0; }
    int n = 0;
    struct Seen {
        dev_t dev;
        ino_t ino;
    } seen[256];
    int seen_count = 0;
    char line[1024];
    while (fgets(line, sizeof(line), fp)) {
        char *path = strchr(line, '/');
        if (!path) continue;
        size_t len = strlen(path);
        if (path[len - 1] == '\n') { path[len - 1] = '\0'; len--; }
        if (!should_consider_so(path)) continue;
        struct stat st;
        if (stat(path, &st) != 0) continue;
        bool duplicate = false;
        for (int i = 0; i < seen_count; ++i) {
            if (seen[i].dev == st.st_dev && seen[i].ino == st.st_ino) {
                duplicate = true;
                break;
            }
        }
        if (duplicate) continue;
        if (seen_count < (int)(sizeof(seen) / sizeof(seen[0]))) {
            seen[seen_count].dev = (dev_t)st.st_dev;
            seen[seen_count].ino = (ino_t)st.st_ino;
            ++seen_count;
        }
        for (const HookEntry *h = g_all_hooks; h->symbol; ++h)
            api->pltHookRegister(st.st_dev, st.st_ino, h->symbol, h->newFunc, h->origFunc);
        ++n;
    }
    fclose(fp);
    return n;
}

// ---- Zygisk module ------------------------------------------------------

static bool jstring_has(JNIEnv *env, jstring value, const char *needle) {
    if (!env || !value || !needle) return false;
    const char *chars = env->GetStringUTFChars(value, nullptr);
    if (!chars) return false;
    bool found = strstr(chars, needle) != nullptr;
    env->ReleaseStringUTFChars(value, chars);
    return found;
}

static bool should_install_for_app(JNIEnv *env, zygisk::AppSpecializeArgs *args) {
    if (!env || !args) return false;

    const bool match =
        jstring_has(env, args->nice_name, "com.eltavine.duckdetector") ||
        jstring_has(env, args->nice_name, "duckdetector") ||
        jstring_has(env, args->nice_name, "DirtySepolicy") ||
        jstring_has(env, args->nice_name, "dirtysepolicy") ||
        jstring_has(env, args->app_data_dir, "com.eltavine.duckdetector") ||
        jstring_has(env, args->app_data_dir, "duckdetector") ||
        jstring_has(env, args->app_data_dir, "DirtySepolicy") ||
        jstring_has(env, args->app_data_dir, "dirtysepolicy");

    if (match) {
        LOGI("[app] target matched child_zygote=%d",
             args->is_child_zygote ? (int)*args->is_child_zygote : -1);
    }
    return match;
}

class DirtySepBypass : public zygisk::ModuleBase {
public:
    void onLoad(zygisk::Api *api, JNIEnv *env) override {
        this->api = api;
        this->env = env;
        LOGD("onLoad");
    }
    void preAppSpecialize(zygisk::AppSpecializeArgs *args) override {
        target_app = should_install_for_app(env, args);
        if (!target_app) {
            if (api) api->setOption(zygisk::DLCLOSE_MODULE_LIBRARY);
            return;
        }
    }
    void postAppSpecialize(const zygisk::AppSpecializeArgs *) override {
        if (target_app)
            install("app");
    }
    void preServerSpecialize(zygisk::ServerSpecializeArgs *) override {
        if (api) api->setOption(zygisk::DLCLOSE_MODULE_LIBRARY);
        LOGD("[server] skip app-side GOT hooks");
    }
private:
    zygisk::Api *api = nullptr;
    JNIEnv *env = nullptr;
    bool target_app = false;
    void install(const char *who) {
        LOGI("[%s] install begin", who);
        hook_jni(env);
        detect_kernel_version();
        resolve_hidden_bits();
        int n = manual_hook_libs();
        if (n > 0) { LOGI("[%s] manual GOT hooks installed on %d libs", who, n); return; }
        int m = register_against_all_libs(api);
        if (m == 0) { LOGW("[%s] no .so libs found to hook", who); return; }
        if (!api->pltHookCommit()) {
            LOGW("[%s] pltHookCommit failed after registering %d libs", who, m);
        } else {
            LOGI("[%s] zygisk PLT hooks committed across %d libs", who, m);
        }
    }
};

static void companion_handler(int client) {
    (void)client;
}

REGISTER_ZYGISK_MODULE(DirtySepBypass)
REGISTER_ZYGISK_COMPANION(companion_handler)
