#!/usr/bin/env bash
# Stream the one-variable Secure Payload test and read the SCREEN, not EP1.
set -euo pipefail
REPO="/home/chanz22/Documents/GitHub/exynos9825-payloads"
HOUSTON="$REPO/../houston-pub"
PAYLOAD="$REPO/build/epbl_custom_key_efuse_probe.bin"
CHAIN="$REPO/build/ldfw_probe_chain/sboot"
OUT="/tmp/exynos9825_ldfw_probe.bin"

[[ -f "$CHAIN/u-boot.bin" ]] || {
    echo "error: build it first with tools/build_ldfw_probe_chain.sh" >&2
    exit 1
}
make -C "$REPO" build/epbl_custom_key_efuse_probe.bin
python3 "$REPO/tools/check_ldfw_observe_image.py" --download --ldfw-hang "$CHAIN/u-boot.bin"

cat <<EOF

Nothing is flashed and no OTP command exists in this image.

This is ecdsa_eng's proven Download path plus exactly one behaviour: the
Secure Payload is allowed to load. Read the SCREEN; EP1 goes away right after
the EL3 monitor is loaded, so it will not carry u-boot's output.

  Samsung Download/Odin screen  -> the Secure Payload loaded and the chain
                                   survived it. The CSMC broker exists, and
                                   the fuse route's main obstacle is gone.
  black screen                  -> loading the Secure Payload is itself what
                                   kills the chain. That is new and precise.

Also say whether a new USB device appears (dmesg / lsusb), because the Odin
gadget enumerating is the same signal as the screen and is easier to be sure
about.

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
