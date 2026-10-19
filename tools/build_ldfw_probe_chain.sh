#!/usr/bin/env bash
# One variable against the chain that is already proven to reach Download mode.
#
# ecdsa_eng, streamed over USB, reaches the Samsung Download screen. This
# chain is the same thing plus exactly one behaviour: the Secure Payload is
# allowed to load. The fork is still forced to Download, so the screen stays
# the oracle -- the only channel on this board that is known to work, now
# that EP1 is observed to disappear right after the EL3 monitor is loaded.
#
#   Download screen  -> the Secure Payload loaded and the chain survived it;
#                       the CSMC broker exists and the fuse route is open
#   black screen     -> loading the Secure Payload is itself what kills it
#
# No OTP command is present. Nothing is written to UFS.
set -euo pipefail

REPO="/home/chanz22/Documents/GitHub/exynos9825-payloads"
CUSTOM="/home/chanz22/EUB-N10/9825_customkey"
CHAIN="$REPO/build/ldfw_probe_chain"

mkdir -p "$CHAIN"
(
    cd "$CUSTOM"
    python3 scripts/split.py s5e9825 input "$CHAIN"
    python3 scripts/patch_9825.py "$CHAIN/sboot/u-boot.bin"
)

# --force-download keeps the proven visible outcome; patch_ignore_magic_code
# comes with it and opens the first secure-payload gate, --force-secure-payload
# opens the second. Deliberately NO --clear-boot-magic: that trampoline is an
# untested suspect and this run is meant to have one variable.
python3 "$REPO/tools/sboot_patch.py" "$CHAIN/sboot/u-boot.bin" \
    --force-download --force-secure-payload --probe-ldfw-result --no-eng

python3 "$REPO/tools/check_ldfw_observe_image.py" --download --ldfw-hang "$CHAIN/sboot/u-boot.bin"

(
    cd "$CUSTOM"
    python3 scripts/build.py s5e9825 keys "$CHAIN"
    python3 scripts/verify_9825.py "$CHAIN/sboot.bin"
)
echo
sha256sum "$CHAIN/sboot.bin"
