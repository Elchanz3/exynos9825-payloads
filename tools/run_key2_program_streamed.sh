#!/usr/bin/env bash
# Program the custom KEY2 trust anchor over the route that works.
#
# THIS BURNS A ONE-SHOT FUSE. It cannot be undone.
#
# WHY STREAMED
#   run_key2_program.sh boots its chain from UFS, and the UFS path is
#   unexplained and black for every image of ours. The streamed route is the
#   one that reached the OTP service on hardware: run_otpcheck got
#   "hasn't been programed yet" back from command 0x114, over the same
#   32-byte buffer path command 0x16 uses. Same chain shape, same two
#   secure-payload patches, one command changed.
#
# WHAT IT DOES AND DOES NOT DO
#   Programs KEY2 only. It does NOT set USE_KEY2, so the BootROM's selector
#   keeps returning the fused KEY slot and the board goes on booting exactly
#   as it does today. That is the point: the value can be read back and the
#   SEC0/SEC1 bits can be measured before anything commits to it.
#
# THE RESIDUAL RISK, STATED PLAINLY
#   Nothing proves command 0x16 does not also set USE_KEY2 internally. The
#   existence of separate commands 0x17 and 0x18 argues against it; cm.bin is
#   encrypted, so the handler cannot be read to settle it. If 0x16 does
#   commit, the board stops accepting Samsung-signed bootloaders, Odin goes
#   with them, and it is EUB-only until our chain boots from UFS or BAN_KEY2
#   works -- and BAN_KEY2 rests on the same unproven C/D mapping.
#
# PRECONDITIONS
#   - our re-signed cm.bin on the CM partition, or the LDFW will not come up
#     and the success path this chain is gated on never runs
#   - battery connected
set -euo pipefail

REPO="/home/chanz22/Documents/GitHub/exynos9825-payloads"
CUSTOM="/home/chanz22/EUB-N10/9825_customkey"
HOUSTON="$REPO/../houston-pub"
CHAIN="$REPO/build/key2_program_streamed_chain/sboot"
PAYLOAD="$REPO/build/epbl_custom_key_efuse_probe.bin"
OUT="/tmp/exynos9825_key2_program_streamed.bin"

[[ -f "$CHAIN/u-boot.bin" ]] || {
    echo "error: build it first with tools/build_key2_fuse_chain.sh program-streamed" >&2
    exit 1
}

make -C "$REPO" build/epbl_custom_key_efuse_probe.bin
python3 "$REPO/tools/check_custom_key.py" "$PAYLOAD" --candidate efuse
python3 "$REPO/tools/check_key2_fuse_image.py" program \
    "$REPO/build/key2_program_streamed_chain"

cat <<'EOF'

================================================================
  THIS RUN BURNS THE KEY2 FUSE. IT CANNOT BE UNDONE.
================================================================

What is gated, and verified by the check above:

  the OTP command runs only when x30 holds 0xc90a64a8, the return
  address of the CM/LDFW initializer's success path. The other nine
  callers of check_signature reach the stub and no-op.

  the three LDFW failure paths are asserted NOT to reach the stub.

What is not gated:

  whether command 0x16 also sets USE_KEY2. cm.bin is encrypted and
  the handler cannot be read. If it does, this board becomes
  EUB-only for an indefinite time.

Afterwards, read it back with:

    /home/chanz22/EUB-N10/9825_customkey/run_key_dump_test.sh

KEY2 should hold the anchor and SEC0/SEC1 should be compared against
0x00000001 / 0x10000006 to see which bits the command moved. That
comparison is the measurement gate C has been waiting for.

EOF

read -r -p 'Type exactly: burn key2   ' answer
[[ "$answer" == "burn key2" ]] || { echo "aborted, nothing was sent" >&2; exit 1; }

echo
echo "== sudo authentication (before the EUB window) =="
if sudo -n true 2>/dev/null; then echo "   already cached"
elif [[ -t 0 ]]; then sudo -v
else echo "error: run from a terminal" >&2; exit 1; fi
echo
echo "Wait for 'Waiting for EUB 04e8:1234...', then put the phone in EUB mode."
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
