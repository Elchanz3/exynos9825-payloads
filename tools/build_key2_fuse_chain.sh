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
    use-streamed)
        # Set USE_KEY2 only, on the streamed route, for a board whose KEY2
        # slot is already programmed and verified. This is the commit.
        CHAIN="$REPO/build/key2_use_streamed_chain"
        FUSE_MODE="use"
        CHECK_MODE="use"
        STREAMED=yes
        ;;
    program-streamed)
        # The same KEY2-only programming chain, built for the route that
        # actually works. The UFS boot is unexplained and black, but the
        # streamed route reached the OTP service on hardware: run_otpcheck
        # got "hasn't been programed yet" back from command 0x114, over the
        # same 32-byte buffer path command 0x16 uses.
        #
        # Two extra patches carry it there, both taken from the otpcheck
        # chain that proved them: --force-secure-payload opens the load, and
        # --ignore-secpayload-sentinel gets past the 0xfa11 word the failed
        # load leaves behind, which otherwise makes the CM/LDFW initializer
        # return before it reads the CM partition.
        CHAIN="$REPO/build/key2_program_streamed_chain"
        FUSE_MODE="key2"
        CHECK_MODE="program"
        STREAMED=yes
        ;;
    *)
        echo "usage: $0 {program|program-use|program-streamed|use-streamed}" >&2
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
# Wire the installed KEY2 stub to the CM/LDFW initializer's SUCCESS path only.
# The other three results are failure paths where the LDFW never came up, and
# the OTP service does not exist there; see patch_key2_after_ldfw.
if [[ "${STREAMED:-no}" == yes ]]; then
    python3 "$REPO/tools/sboot_patch.py" "$CHAIN/sboot/u-boot.bin" \
        --normal-boot --force-secure-payload --ignore-secpayload-sentinel \
        --key2-post-ldfw --no-eng
else
    python3 "$REPO/tools/sboot_patch.py" \
        "$CHAIN/sboot/u-boot.bin" --normal-boot --key2-post-ldfw --no-eng
fi

(
    cd "$CUSTOM"
    python3 scripts/build.py s5e9825 keys "$CHAIN"
)

python3 "$REPO/tools/check_key2_fuse_image.py" "$CHECK_MODE" "$CHAIN"
(
    cd "$CUSTOM"
    python3 scripts/verify_9825.py "$CHAIN/sboot.bin"
)
