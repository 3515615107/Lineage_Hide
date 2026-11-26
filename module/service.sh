#!/system/bin/sh

resetprop -w init.svc.bootanim "running"

[ $(realpath "/proc/$$/exe") != "/system/bin/sh" ] && exec "/system/bin/sh" "$0"

for i in "/system/build.prop" "/product/etc/build.prop" "/system_ext/etc/build.prop" "/system/system_dlkm/etc/build.prop"
do
    mp=$(df "$i" | awk 'NR==2 {print $6}')
    mount -o remount,rw "$mp"
    sed -i 's/userdebug/user/g' "$i"
    mount -o remount,ro "$mp"
done

resetprop -w sys.boot_completed 0

pm disable "org.lineageos.jelly"

pm list packages -s | sed 's/^package://' | sort -u > "${0%/*}/system_packages.txt"

resetprop -w sys.user.0.ce_available "false"
until [ -d "/sdcard/Android" ]
do
    sleep 1
done

resetprop -n "ro.boot.flash.locked" "1"
check_reset_prop() {
    local NAME=$1
    local EXPECTED=$2
    local VALUE=$(resetprop $NAME)
    [ -z $VALUE ] || [ $VALUE = $EXPECTED ] || resetprop -n $NAME $EXPECTED
}
contains_reset_prop() {
    local NAME=$1
    local CONTAINS=$2
    local NEWVAL=$3
    [[ "$(resetprop $NAME)" = *"$CONTAINS"* ]] && resetprop -n $NAME $NEWVAL
}
check_reset_prop "ro.boot.verifiedbootstate" "green"
check_reset_prop "ro.debuggable" "0"
check_reset_prop "ro.force.debuggable" "0"
check_reset_prop "ro.secure" "1"
check_reset_prop "ro.adb.secure" "1"
check_reset_prop "ro.build.type" "user"
check_reset_prop "ro.build.tags" "release-keys"
contains_reset_prop "ro.bootmode" "recovery" "unknown"

resetprop -n ro.boot.vbmeta.device_state "locked"
resetprop -n ro.boot.vbmeta.avb_version "1.4"
resetprop -n ro.boot.vbmeta.hash_alg "sha256"
resetprop -n ro.boot.vbmeta.size "4096"

resetprop -n init.svc.adb_root ""

resetprop -n ro.config.ringtone "unknown"

resetprop | awk -F '\\[|\\]: \\[|\\]' '/lineage/ {
    key=$2
    value=$3
    if (key ~ /lineage/) {
        system("exec resetprop --delete \"" key "\"")
    } else if (value ~ /lineage/) {
        gsub("lineage_?", "", value)
        system("exec resetprop \"" key "\" \"" value "\"")
    }
}'

[ -e "/sys/module/susfs_guard_lkm" ] && ksu_susfs() {
    case "$1" in
        "add_sus_path"*)
            echo "add $2" > "/proc/susfs_path"
        ;;
        "add_sus_map")
            echo "add $2" > "/proc/susfs_map"
        ;;
        *)
            command ksu_susfs "$@"
        ;;
    esac
}

ksu_susfs hide_sus_mnts_for_non_su_procs 1
ksu_susfs enable_avc_log_spoofing 1

find "/data/resource-cache" "/system" "/vendor" "/system_ext" "/product" -iname "*lineage*" -o -iname '*gapps*' | while IFS= read -r line
do
    ksu_susfs add_sus_path "$line"
    [ -f "$line" ] && ksu_susfs add_sus_map "$line"
done

ksu_susfs add_sus_path "/system/addon.d"
ksu_susfs add_sus_path "/data/lineageos_updates"
ksu_susfs add_sus_path_loop "/system/lib64/libstagefright.so"
ksu_susfs add_sus_path "/data/adbroot"

ksu_susfs add_sus_path_loop "/vendor/etc/selinux/vendor_file_contexts"
ksu_susfs add_sus_path_loop "/system_ext/etc/selinux/system_ext_sepolicy.cil"
ksu_susfs add_sus_path_loop "/vendor/etc/selinux/vendor_sepolicy.cil"
ksu_susfs add_sus_map "/data/adb/modules/zygisksu/lib64/libzygisk.so"
ksu_susfs add_sus_map "/data/adb/modules/lineage_hide/zygisk/arm64-v8a.so"

sleep 30
ksu_susfs add_sus_path_loop "/vendor/etc/selinux/vendor_hwservice_contexts"
ksu_susfs add_sus_path_loop "/system_ext/etc/init/init.lineage-system_ext.rc"
ksu_susfs add_sus_path "/system_ext/etc/permissions"
