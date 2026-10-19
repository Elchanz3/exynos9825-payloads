#!/usr/bin/env bash
# Stream the one-variable Secure Payload test and read the SCREEN, not EP1.
set -euo pipefail
REPO="/home/chanz22/Documents/GitHub/exynos9825-payloads"
HOUSTON="$REPO/../houston-pub"
PAYLOAD="$REPO/build/epbl_custom_key_efuse_probe.bin"
CHAIN="$REPO/build/ldfwsignal_chain/sboot"
OUT="/tmp/exynos9825_ldfwsignal.bin"

[[ -f "$CHAIN/u-boot.bin" ]] || {
    echo "error: build it first with tools/build_ldfwsignal_chain.sh" >&2
    exit 1
}
make -C "$REPO" build/epbl_custom_key_efuse_probe.bin
python3 "$REPO/tools/check_ldfw_observe_image.py" --ldfwsignal "$CHAIN/u-boot.bin"

cat <<EOF

Nothing is flashed and no OTP command exists in this image.

With the prompt stubbed the last run went black, so the chain passes the
secure-payload dead end and then stops with nothing drawing. There is no
output channel left on this path -- no UART, and EP1 is gone after the EL3
monitor -- so this run moves the one thing that is proven to draw.

The blue USB RECOVERY MODE prompt is left intact, but:

  * the tail branch that reached it from the failed secure-payload block is
    now `ret`, so it is no longer the normal path's dead end;
  * the CM/LDFW success diagnostic calls it instead of printf.

Read the SCREEN:

  blue USB RECOVERY MODE  -> "ldfw: try to init N ldfw(s)" was REACHED.
        The CM/LDFW initializer ran and succeeded. That is the one fact the
        fuse route depends on, and it would mean OTP 0x16 can finally be
        answered.
  anything else / black   -> that path was not reached. A crash cannot draw
        a prompt, so this direction stays unambiguous.

== sudo authentication (before the EUB window) ==
EOF
if sudo -n true 2>/dev/null; then echo "   already cached"; elif [[ -t 0 ]]; then sudo -v; else
    echo "error: run from a terminal" >&2; exit 1; fi
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
