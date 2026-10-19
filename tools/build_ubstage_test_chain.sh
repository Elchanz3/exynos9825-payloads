#!/usr/bin/env bash
# Build a custom-signed chain whose complete u-boot reports entry by entering
# its own Samsung Download mode.

set -euo pipefail

REPO="/home/chanz22/Documents/GitHub/exynos9825-payloads"
CUSTOM="/home/chanz22/EUB-N10/9825_customkey"
CHAIN="$REPO/build/ubstage_test_chain"
IMAGE="$CHAIN/sboot.bin"
STAGE="$REPO/build/ubstage_download_marker.bin"
BASE="$CHAIN/u-boot.base.bin"
PROVEN="$CUSTOM/ecdsa_eng/sboot/u-boot.bin"

make -C "$REPO" build/ubstage_download_marker.bin

# This is a generated test artifact. Recreate it from the same stock input on
# every build so no patch from the KEY2 programming chain can leak into it.
rm -rf "$CHAIN"
mkdir -p "$CHAIN"

(
    cd "$CUSTOM"
    python3 scripts/split.py s5e9825 input "$CHAIN"
)

# Apply only the engineering patches. Explicitly remove both fuse environment
# variables so this diagnostic can never acquire the KEY2 programming stub
# from the caller's shell.
(
    cd "$CUSTOM"
    env -u FUSE_BOOT_KEY -u FUSE_MODE \
        python3 scripts/patch_9825.py "$CHAIN/sboot/u-boot.bin"
)

python3 "$REPO/tools/install_ubstage_download_marker.py" \
    "$STAGE" "$CHAIN/sboot/u-boot.bin" "$BASE"

(
    cd "$CUSTOM"
    python3 scripts/build.py s5e9825 keys "$CHAIN"
)

python3 - "$STAGE" "$BASE" "$CHAIN/sboot/u-boot.bin" "$PROVEN" <<'PY'
import hashlib
import struct
import sys
from pathlib import Path

stage_path = Path(sys.argv[1])
base_path = Path(sys.argv[2])
slot_path = Path(sys.argv[3])
proven_path = Path(sys.argv[4])
stage = stage_path.read_bytes()
base = base_path.read_bytes()
slot = slot_path.read_bytes()
proven = proven_path.read_bytes()
footer = len(slot) - 0x210
CAVE = 0x17CE00
LOAD = 0xC9000000

def u32(data, offset):
    return struct.unpack_from("<I", data, offset)[0]

def resolve_b(value, address):
    if value & 0xFC000000 != 0x14000000:
        raise SystemExit(f"error: {address:#x} is not an unconditional branch")
    imm = value & 0x03FFFFFF
    if imm & (1 << 25):
        imm -= 1 << 26
    return address + imm * 4

if len(base) != 0x180000 or len(slot) != len(base):
    raise SystemExit("error: unexpected u-boot slot size")
if len(proven) != len(base) or proven[:footer] != base[:footer]:
    raise SystemExit("error: diagnostic base differs from the proven ecdsa_eng body")
if base[0x4FC68:0x4FC70] != bytes.fromhex("00 00 80 d2 c0 03 5f d6"):
    raise SystemExit("error: diagnostic u-boot contains an unexpected signature stub")
if resolve_b(u32(slot, 0), LOAD) != LOAD + CAVE:
    raise SystemExit("error: u-boot entry does not branch to the marker cave")
if slot[CAVE:CAVE + len(stage) - 4] != stage[:-4]:
    raise SystemExit("error: signed u-boot slot does not contain the entry marker")
resume_at = LOAD + CAVE + len(stage) - 4
if resolve_b(u32(slot, CAVE + len(stage) - 4), resume_at) != LOAD + 4:
    raise SystemExit("error: marker does not resume the original u-boot entry")

allowed = set(range(0, 4))
allowed.update(range(CAVE, CAVE + len(stage)))
allowed.update(range(footer, len(slot)))
unexpected = [i for i, (before, after) in enumerate(zip(base, slot))
              if before != after and i not in allowed]
if unexpected:
    raise SystemExit(
        f"error: signed u-boot has an unexpected change at {unexpected[0]:#x}"
    )

print(f"entry marker     {stage_path}")
print(f"marker sha256    {hashlib.sha256(stage).hexdigest()}")
print(f"full u-boot base {base_path}")
print(f"base sha256      {hashlib.sha256(base).hexdigest()}")
print("base body matches proven ecdsa_eng = YES")
print(f"u-boot slot {slot_path}")
print(f"u-boot sha256 {hashlib.sha256(slot).hexdigest()}")
print("OTP injection = ABSENT")
print("entry marker verification = PASS")
PY

(
    cd "$CUSTOM"
    python3 scripts/verify_9825.py "$IMAGE"
)

echo "sboot sha256 $(sha256sum "$IMAGE" | awk '{print $1}')"

cat <<EOF

Diagnostic BOOTLOADER image (complete u-boot with Download-mode entry marker):
  $IMAGE
EOF
