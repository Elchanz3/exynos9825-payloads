#!/usr/bin/env bash
# Build and validate an Exynos9825 chain that programs the custom KEY2 anchor.

set -euo pipefail

REPO="/home/chanz22/Documents/GitHub/exynos9825-payloads"
CUSTOM="/home/chanz22/EUB-N10/9825_customkey"
MODE="${1:-program}"

case "$MODE" in
    program)
        CHAIN="$REPO/build/key2_program_chain"
        FUSE_MODE="key2"
        CHECK_MODE="program"
        ;;
    program-use)
        CHAIN="$REPO/build/key2_program_use_chain"
        FUSE_MODE="key2+use"
        CHECK_MODE="program-use"
        ;;
    *)
        echo "usage: $0 {program|program-use}" >&2
        exit 2
        ;;
esac

mkdir -p "$CHAIN"

(
    cd "$CUSTOM"
    python3 scripts/split.py s5e9825 input "$CHAIN"
    FUSE_BOOT_KEY=yes-burn-key2 FUSE_MODE="$FUSE_MODE" \
        python3 scripts/patch_9825.py "$CHAIN/sboot/u-boot.bin"
)

# USB/EUB leaves both the LDFW early-exit words and a live cable request. Patch
# the u-boot reads after BL2 has initialized DRAM, and make the later download
# fork take the normal path while preserving w0 as the legitimate zero reason.
# Retry the installed KEY2 stub on every CM/LDFW initializer result path; those
# paths are mutually exclusive, so exactly one post-initializer attempt runs.
python3 "$REPO/tools/sboot_patch.py" \
    "$CHAIN/sboot/u-boot.bin" --normal-boot --key2-post-ldfw --no-eng

(
    cd "$CUSTOM"
    python3 scripts/build.py s5e9825 keys "$CHAIN"
)

python3 "$REPO/tools/check_key2_fuse_image.py" "$CHECK_MODE" "$CHAIN"
(
    cd "$CUSTOM"
    python3 scripts/verify_9825.py "$CHAIN/sboot.bin"
)
