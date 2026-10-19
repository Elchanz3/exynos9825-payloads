#!/usr/bin/env bash
# Build a custom-signed chain whose u-boot is forced into Samsung Download mode.

set -euo pipefail

REPO="/home/chanz22/Documents/GitHub/exynos9825-payloads"
CUSTOM="/home/chanz22/EUB-N10/9825_customkey"
CHAIN="$REPO/build/ubstage_forced_download_chain"
IMAGE="$CHAIN/sboot.bin"
BASE="$CHAIN/u-boot.base.bin"
PROVEN="$CUSTOM/ecdsa_eng/sboot/u-boot.bin"

# Recreate the generated chain from the same stock input on every explicit
# build. The trigger action validates the existing artifact and never rebuilds
# it, so the file checked there is exactly the file the user flashed.
rm -rf "$CHAIN"
mkdir -p "$CHAIN"

(
    cd "$CUSTOM"
    python3 scripts/split.py s5e9825 input "$CHAIN"
)

# Reproduce the proven ecdsa_eng body without inheriting any fuse environment.
(
    cd "$CUSTOM"
    env -u FUSE_BOOT_KEY -u FUSE_MODE \
        python3 scripts/patch_9825.py "$CHAIN/sboot/u-boot.bin"
)

cp "$CHAIN/sboot/u-boot.bin" "$BASE"
python3 "$REPO/tools/sboot_patch.py" \
    "$CHAIN/sboot/u-boot.bin" --force-download --no-eng

(
    cd "$CUSTOM"
    python3 scripts/build.py s5e9825 keys "$CHAIN"
)

python3 "$REPO/tools/check_ubstage_forced_download.py" \
    "$BASE" "$CHAIN/sboot/u-boot.bin" "$PROVEN"

(
    cd "$CUSTOM"
    python3 scripts/verify_9825.py "$IMAGE"
)

cat <<EOF

Forced-Download BOOTLOADER image:
  $IMAGE

sboot sha256 $(sha256sum "$IMAGE" | awk '{print $1}')
EOF
