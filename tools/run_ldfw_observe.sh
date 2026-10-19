#!/usr/bin/env bash
# Stream the LDFW-observation chain over USB and watch what u-boot says.
#
# This is the one question that has to be answered before any fuse attempt,
# and it can be answered with no irreversible step: does the Secure Payload
# load, and does the CM/LDFW initializer succeed? Until both are true, OTP
# command 0x16 can only ever return -1.
#
# Nothing is written to UFS and no OTP command exists in this image --
# check_ldfw_observe_image.py refuses to build one that has a path to it.
set -euo pipefail

REPO="/home/chanz22/Documents/GitHub/exynos9825-payloads"
HOUSTON="$REPO/../houston-pub"
PAYLOAD="$REPO/build/epbl_custom_key_efuse_probe.bin"
CHAIN="$REPO/build/ldfw_observe_chain/sboot"
OUT="/tmp/exynos9825_ldfw_observe.bin"

[[ -f "$CHAIN/u-boot.bin" ]] || {
    echo "error: build it first with tools/build_ldfw_observe_chain.sh" >&2
    exit 1
}
make -C "$REPO" build/epbl_custom_key_efuse_probe.bin
python3 "$REPO/tools/check_ldfw_observe_image.py" "$CHAIN/u-boot.bin"
python3 "$REPO/tools/check_custom_key.py" "$PAYLOAD"

cat <<EOF

Nothing is flashed and no OTP command is issued. The chain is streamed into
RAM; a power cycle leaves the board exactly as it is now.

What to look for in the EP1 console output:

  "Start to Load" / "Load done."        the Secure Payload loaded
  "Skip to load Secure Payload"         the gate patch did not take
  "Fail to load Secure Payload!!"       it tried and failed; the ret code matters

  "ldfw: try to init N ldfw(s)..."      the CM/LDFW initializer ran
  "ldfw: No ldfw is inited"             it ran and found nothing
  "ldfw: signature of ldfw is corrupted" it ran and rejected the CM partition

The pass condition for the fuse route is the Secure Payload loading AND the
initializer reporting a non-zero count. Anything else means the OTP command
would still return -1, and arming it would be pointless rather than risky.

Report the console output verbatim, plus what the screen did.

== sudo authentication (before the EUB window) ==
EOF
if sudo -n true 2>/dev/null; then
    echo "   already cached, nothing to do"
elif [[ -t 0 ]]; then
    sudo -v
else
    echo "error: run from a terminal so sudo can prompt before EUB mode" >&2
    exit 1
fi
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
