# shellcheck shell=sh
# MIMXRT700 XSPI guest fence: wolfBoot arms one FRAD over both guest windows
# each boot and a WT_GUEST_FLASH_WRP=1 wolfTrust verifies it. The bounds use
# the wolfTrust build's own layout values, so they cannot drift. Needs $repo.

rt700_layout_value() {
    eval "rt700_v=\${$1:-}"
    if [ -z "$rt700_v" ]; then
        # shellcheck disable=SC2154  # $repo is set by the sourcing runner
        rt700_v=$(awk -v n="$1" '$1 == n && $2 == "?=" { print $3; exit }' \
            "$repo/mk/target-mimxrt700.mk")
    fi
    printf '%s' "$rt700_v"
}

# Sets RT700_GUEST_FENCE_START/END (END exclusive); fails when the guest
# windows are not contiguous or not on the 64 KB FRAD granule.
rt700_fence_bounds() {
    g0=$(rt700_layout_value WT_GUEST0_FLASH_BASE)
    g0s=$(rt700_layout_value WT_GUEST0_FLASH_SIZE)
    g1=$(rt700_layout_value WT_GUEST1_FLASH_BASE)
    g1s=$(rt700_layout_value WT_GUEST1_FLASH_SIZE)
    if [ -z "$g0" ] || [ -z "$g0s" ] || [ -z "$g1" ] || [ -z "$g1s" ]; then
        echo "rt700 fence: guest layout not found in mk/target-mimxrt700.mk" >&2
        return 1
    fi
    if [ $((g0 + g0s)) -ne $((g1)) ]; then
        echo "rt700 fence: guest windows are not contiguous" >&2
        return 1
    fi
    if [ $((g0 & 0xFFFF)) -ne 0 ] || [ $(((g1 + g1s) & 0xFFFF)) -ne 0 ]; then
        echo "rt700 fence: guest windows are not 64 KB aligned" >&2
        return 1
    fi
    RT700_GUEST_FENCE_START=$(printf '0x%08X' $((g0)))
    RT700_GUEST_FENCE_END=$(printf '0x%08X' $((g1 + g1s)))
}

# The wolfBoot CFLAGS_EXTRA that arms the fence (tests/target/
# wolfboot-imxrt700-guest-fence.patch reads these two defines).
rt700_fence_cflags() {
    rt700_fence_bounds || return 1
    printf '%s' "-DXSPI_GUEST_FENCE_START=$RT700_GUEST_FENCE_START" \
        " -DXSPI_GUEST_FENCE_END=$RT700_GUEST_FENCE_END"
}
