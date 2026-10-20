#!/usr/bin/env bash
# Set USE_KEY2. This is the commit.
#
# AFTER THIS THE BOOTROM STOPS CONSULTING SAMSUNG'S KEY.
#
# The board then boots a chain signed with our key, or it boots nothing. Odin
# lives inside sboot, so if our sboot is not already on BOOTLOADER and
# verifying, Download mode goes with it and EUB is the only way back in.
#
# WHY A SEPARATE MODE
#   key2+use runs 0x16 first and skips 0x17 if it returns nonzero. The slot is
#   already programmed, so 0x16 may well report an error against it and the
#   guard would eat the run. This chain carries 0x17 alone.
#
# PRECONDITIONS, AND THEY ARE NOT OPTIONAL
#   - KEY2 already programmed and read back correct (run_key_dump_test)
#   - OUR sboot on BOOTLOADER        ecdsa_eng/sboot.bin
#   - OUR cm.bin on CM               build/custom_cm/cm.bin
#   Both must be flashed BEFORE this runs, while Odin still works. Flashing
#   them makes the board stop cold-booting, which is expected: the fuse is
#   what makes it boot again.
#
# THE ESCAPE HATCH IS UNPROVEN
#   BAN_KEY2 (0x18) is believed to restore the KEY path by setting D, on the
#   inference that C and D are the USE/BAN pair. Programming KEY2 moved
#   neither bit, so that inference was never tested and this run is the first
#   thing that would show it.
set -euo pipefail

REPO="/home/chanz22/Documents/GitHub/exynos9825-payloads"
CUSTOM="/home/chanz22/EUB-N10/9825_customkey"
HOUSTON="$REPO/../houston-pub"
CHAIN="$REPO/build/key2_use_streamed_chain/sboot"
PAYLOAD="$REPO/build/epbl_custom_key_efuse_probe.bin"
OUT="/tmp/exynos9825_key2_use_streamed.bin"

[[ -f "$CHAIN/u-boot.bin" ]] || {
    echo "error: build it first with tools/build_key2_fuse_chain.sh use-streamed" >&2
    exit 1
}

make -C "$REPO" build/epbl_custom_key_efuse_probe.bin
python3 "$REPO/tools/check_custom_key.py" "$PAYLOAD" --candidate efuse
python3 "$REPO/tools/check_key2_fuse_image.py" use \
    "$REPO/build/key2_use_streamed_chain"

cat <<'EOF'

================================================================
  THIS SETS USE_KEY2. IT IS THE POINT OF NO RETURN.
================================================================

After it, the BootROM verifies against our KEY2 and stops accepting
Samsung-signed bootloaders. The board boots our chain or nothing.

Confirm each of these is already true. The host cannot check them.

  1. KEY2 reads back as our anchor
     1d12d364cf441dfe7d5084a054691cf1c7f71e068e2470881e52ce280c7c330b

  2. OUR sboot is on BOOTLOADER
     /home/chanz22/EUB-N10/9825_customkey/ecdsa_eng/sboot.bin

  3. OUR cm.bin is on CM
     /home/chanz22/Documents/GitHub/exynos9825-payloads/build/custom_cm/cm.bin

If 2 or 3 is wrong, the board will not boot afterwards and Odin will not
be there to fix it. EUB would be the only way in, and the way back out
rests on BAN_KEY2, which has never been tested.

EOF

read -r -p 'Is our sboot on BOOTLOADER and our cm.bin on CM? (yes/no)  ' pre
[[ "$pre" == "yes" ]] || { echo "aborted, nothing was sent" >&2; exit 1; }
read -r -p 'Type exactly: commit to key2   ' answer
[[ "$answer" == "commit to key2" ]] || { echo "aborted, nothing was sent" >&2; exit 1; }

echo
echo "== sudo authentication (before the EUB window) =="
if sudo -n true 2>/dev/null; then echo "   already cached"
elif [[ -t 0 ]]; then sudo -v
else echo "error: run from a terminal" >&2; exit 1; fi
echo
echo "Wait for 'Waiting for EUB 04e8:1234...', then put the phone in EUB mode."
echo
echo "Afterwards, read the state back:"
echo "  /home/chanz22/EUB-N10/9825_customkey/run_key_state_test.sh"
echo "SEC0 bit 1 should now be set and the selector should pick 0x10003020."
echo
exec sudo "$HOUSTON/.venv/bin/python3" "$REPO/tools/boot_nonsecure_probe.py" \
    --houston-dir "$HOUSTON" \
    --payload "$PAYLOAD" \
    --allow-unpinned-stages \
    --receive-test \
    --receive-file "$CHAIN/epbl.bin" \
    --receive-next-file "$CHAIN/fwbl1.bin" \
    --receive-next-file "$CHAIN/bl2.bin" \
    --receive-next-file "$CHAIN/u-boot.bin" \
    --receive-next-file "$CHAIN/el3_mon.bin" \
    --output "$OUT"
