#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0
#
# selinux_hide_patch.sh - block privileged SELinux context probes from
# application UIDs in KernelSU's selinux_hide feature.
#
# The patch adds three guards that make the backup-policy fallback refuse
# to answer for privileged domains, so an app (uid >= 10000) cannot deduce
# the hidden SELinux state through /sys/fs/selinux:
#   - my_write_context(): reject "u:r:adbroot:s0"
#   - my_write_access():  reject "u:r:shell:s0" + "u:r:su:s0",
#                         "u:r:fsck_untrusted:s0", "u:r:adbroot:s0"
#   - ksu_handle_selinux_setprocattr(): reject "u:r:adbroot:s0"
#
# It also keeps the KSU commit SHA free of the "-dirty" suffix.
#
# Usage:
#   scripts/selinux_hide_patch.sh [--check|--revert] <tree>
#
# <tree> is either the kernel source root (KernelSU is cloned at
# <tree>/KernelSU and symlinked as drivers/kernelsu) or the KernelSU repo
# root itself.
set -euo pipefail

usage() {
    cat <<'EOF'
Usage: selinux_hide_patch.sh [--check|--revert] <tree>

  (no option)  apply the SELinux context guards
  --check      report whether the guards are fully in place; no changes
  --revert     remove the guards again

<tree> is the kernel source root (contains KernelSU/) or the KernelSU repo
root (contains kernel/Kbuild).

Examples:
  scripts/selinux_hide_patch.sh /path/to/kernel
  scripts/selinux_hide_patch.sh --check /path/to/kernel/KernelSU
  scripts/selinux_hide_patch.sh --revert /path/to/kernel

Rebuild and flash the kernel after applying.  A backup of each edited file is
written next to it as *.selinux_hide.bak.
EOF
}

MODE=apply
KDIR=
while [ $# -gt 0 ]; do
    case "$1" in
        --check) MODE=check ;;
        --revert) MODE=revert ;;
        -h|--help) usage; exit 0 ;;
        --*) echo "error: unknown option: $1" >&2; usage >&2; exit 2 ;;
        *)
            if [ -n "$KDIR" ]; then
                echo "error: only one tree may be given" >&2
                exit 2
            fi
            KDIR=$1
            ;;
    esac
    shift
done

if [ -z "$KDIR" ]; then
    usage >&2
    exit 2
fi
if [ ! -d "$KDIR" ]; then
    echo "error: '$KDIR' is not a directory" >&2
    exit 1
fi
if ! command -v patch >/dev/null 2>&1; then
    echo "error: patch is required to apply the changes" >&2
    exit 1
fi

KDIR=$(cd "$KDIR" && pwd -P)
KSU_ROOT=
for candidate in "$KDIR" "$KDIR/KernelSU"; do
    if [ -f "$candidate/kernel/Kbuild" ] &&
       [ -f "$candidate/kernel/feature/selinux_hide/selinux_hide_auto.c" ]; then
        KSU_ROOT=$candidate
        break
    fi
done
if [ -z "$KSU_ROOT" ] && [ -e "$KDIR/drivers/kernelsu" ]; then
    # drivers/kernelsu -> KernelSU/kernel
    candidate=$(dirname "$(realpath "$KDIR/drivers/kernelsu")")
    if [ -f "$candidate/kernel/Kbuild" ] &&
       [ -f "$candidate/kernel/feature/selinux_hide/selinux_hide_auto.c" ]; then
        KSU_ROOT=$candidate
    fi
fi
if [ -z "$KSU_ROOT" ]; then
    echo "error: KernelSU tree not found under '$KDIR'" >&2
    echo "       expected kernel/feature/selinux_hide/selinux_hide_auto.c" >&2
    exit 1
fi

PATCH_FILE=$(mktemp "${TMPDIR:-/tmp}/selinux_hide_patch.XXXXXX")
trap 'rm -f "$PATCH_FILE"' EXIT

cat > "$PATCH_FILE" <<'EOF'
diff --git a/kernel/Kbuild b/kernel/Kbuild
index b637cd8e..08b27cdb 100644
--- a/kernel/Kbuild
+++ b/kernel/Kbuild
@@ -82,7 +82,7 @@ KSU_VERSION := $(shell expr 30000 + $(KSU_LOCAL_VERSION) + 700)
 KSU_TAG_NAME    := $(shell cd $(KSU_SRC); $(GIT_BIN) describe --abbrev=0 --tags 2>/dev/null || echo "v4.1.0")
 KSU_COMMIT_SHA  := $(shell cd $(KSU_SRC); $(GIT_BIN) rev-parse --short=8 HEAD 2>/dev/null || echo "unknown")
 ifneq ($(shell cd $(KSU_SRC); $(GIT_BIN) diff-index --quiet HEAD; echo $$?),0)
-KSU_COMMIT_SHA  := $(KSU_COMMIT_SHA)-dirty
+KSU_COMMIT_SHA  := $(KSU_COMMIT_SHA)
 endif
 KSU_BRANCH_NAME := $(shell cd $(KSU_SRC); $(GIT_BIN) branch --show-current 2>/dev/null || echo "unknown")
 
diff --git a/kernel/feature/selinux_hide/selinux_hide_auto.c b/kernel/feature/selinux_hide/selinux_hide_auto.c
index eb268b11..34ada1cf 100644
--- a/kernel/feature/selinux_hide/selinux_hide_auto.c
+++ b/kernel/feature/selinux_hide/selinux_hide_auto.c
@@ -193,6 +193,9 @@ static ssize_t my_write_context(struct file *file, char *buf, size_t size)
     if (likely(ksu_get_uid_t(current_uid()) < 10000)) {
         return orig_context_write(file, buf, size);
     }
+    if (strstr(buf, "u:r:adbroot:s0")) {
+        return -EINVAL;
+    }
     char *canon = NULL;
     u32 sid, len;
     ssize_t length;
@@ -263,6 +266,12 @@ static ssize_t my_write_access(struct file *file, char *buf, size_t size)
     struct av_decision avd;
     ssize_t length;
 
+    if ((strstr(buf, "u:r:shell:s0") && strstr(buf, "u:r:su:s0")) || strstr(buf, "u:r:fsck_untrusted:s0") ||
+        strstr(buf, "u:r:adbroot:s0")) {
+        length = -EINVAL;
+        goto out;
+    }
+
     length = ksu_avc_has_perm_compat(current_sid(), SECINITSID_SECURITY, SECCLASS_SECURITY, SECURITY__COMPUTE_AV, NULL);
     if (length)
         goto out;
@@ -412,6 +421,10 @@ int __nocfi ksu_handle_selinux_setprocattr(struct task_struct *p, char *name, vo
             str[size - 1] = 0;
             size--;
         }
+        // value from proc_pid_attr_write() is not NUL-terminated, use strnstr
+        if (strnstr(str, "u:r:adbroot:s0", size)) {
+            return -EINVAL;
+        }
         error = security_context_to_sid_live(value, size, &sid);
         if (error) {
             return error;
EOF

dry_run() {
    local direction=$1
    if [ "$direction" = reverse ]; then
        patch -R -p1 -d "$KSU_ROOT" --batch --fuzz=0 --forward --dry-run < "$PATCH_FILE" >/dev/null 2>&1
    else
        patch -p1 -d "$KSU_ROOT" --batch --fuzz=0 --forward --dry-run < "$PATCH_FILE" >/dev/null 2>&1
    fi
}

backup_opts=(-b -z .selinux_hide.bak)
if [ "$MODE" = check ]; then
    if dry_run reverse; then
        echo "check: guards are fully applied in $KSU_ROOT"
        exit 0
    fi
    if dry_run forward; then
        echo "check: guards are not applied in $KSU_ROOT"
        exit 1
    fi
    echo "check: tree does not match the expected patched or unpatched state" >&2
    exit 1
fi

if [ "$MODE" = apply ]; then
    if dry_run reverse; then
        echo "already applied; nothing to do"
        exit 0
    fi
    if ! dry_run forward; then
        echo "error: patch does not apply cleanly; the tree may already be partially patched" >&2
        exit 1
    fi
    patch -p1 -d "$KSU_ROOT" --batch --fuzz=0 --forward "${backup_opts[@]}" < "$PATCH_FILE"
    echo "applied; rebuild the kernel and flash it"
    exit 0
fi

if dry_run reverse; then
    patch -R -p1 -d "$KSU_ROOT" --batch --fuzz=0 --forward "${backup_opts[@]}" < "$PATCH_FILE"
    echo "reverted; rebuild the kernel and flash it"
    exit 0
fi
if dry_run forward; then
    echo "not applied; nothing to do"
    exit 0
fi
echo "error: patch cannot be reverted cleanly; the tree may have local changes" >&2
exit 1
