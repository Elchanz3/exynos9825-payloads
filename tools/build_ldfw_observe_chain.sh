#!/usr/bin/env bash
# Build a chain that answers the LDFW question without any irreversible step.
#
# The fuse needs OTP command 0x16, which needs the CSMC broker from the Secure
# Payload plus the CM-partition LDFW initialized. Two gates stop u-boot from
# loading the Secure Payload, and 24 places read the DRAM boot-mode word. This
# chain opens the gates and makes all 24 agree -- and carries NO OTP stub, so
# the only thing it can do is tell us whether the LDFW initializer succeeds.
#
# Stream it over USB; u-boot prints its own LDFW result over the channel:
#   "ldfw: try to init %d ldfw(s). except %d ldfw %d ldfw(s) have been inited"
#   "ldfw: No ldfw is inited"
#   "ldfw: signature of ldfw is corrupted! ret = [0x%llX]"
set -euo pipefail

REPO="/home/chanz22/Documents/GitHub/exynos9825-payloads"
CUSTOM="/home/chanz22/EUB-N10/9825_customkey"
CHAIN="$REPO/build/ldfw_observe_chain"

mkdir -p "$CHAIN"
(
    cd "$CUSTOM"
    python3 scripts/split.py s5e9825 input "$CHAIN"
    # No FUSE_BOOT_KEY: this deliberately takes the branch that leaves
    # check_signature inert instead of turning it into the KEY2 stub.
    python3 scripts/patch_9825.py "$CHAIN/sboot/u-boot.bin"
)

python3 "$REPO/tools/sboot_patch.py" "$CHAIN/sboot/u-boot.bin" \
    --normal-boot --force-secure-payload --clear-boot-magic --no-eng

python3 "$REPO/tools/check_ldfw_observe_image.py" "$CHAIN/sboot/u-boot.bin"

(
    cd "$CUSTOM"
    python3 scripts/build.py s5e9825 keys "$CHAIN"
    python3 scripts/verify_9825.py "$CHAIN/sboot.bin"
)
echo
echo "chain: $CHAIN/sboot.bin"
sha256sum "$CHAIN/sboot.bin"
