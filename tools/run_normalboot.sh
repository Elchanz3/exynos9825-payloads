#!/usr/bin/env bash
# Stream the one-variable Secure Payload test and read the SCREEN, not EP1.
set -euo pipefail
REPO="/home/chanz22/Documents/GitHub/exynos9825-payloads"
HOUSTON="$REPO/../houston-pub"
PAYLOAD="$REPO/build/epbl_custom_key_efuse_probe.bin"
CHAIN="$REPO/build/normalboot_chain/sboot"
OUT="/tmp/exynos9825_normalboot.bin"

[[ -f "$CHAIN/u-boot.bin" ]] || {
    echo "error: build it first with tools/build_normalboot_chain.sh" >&2
    exit 1
}
make -C "$REPO" build/epbl_custom_key_efuse_probe.bin
python3 "$REPO/tools/check_ldfw_observe_image.py" --normalboot "$CHAIN/u-boot.bin"

cat <<EOF

Nothing is flashed and no OTP command exists in this image.

Last run showed the blue USB RECOVERY MODE prompt and then rebooted. That
prompt is the tail of the secure-payload block: the load fails, u-boot prints
"Fail to load Secure Payload!!" and the debug info, then tail-branches into
the prompt, waits for a key, and writes the download magic back to
0x80000000 on its way out. It is a dead end, not a failure of the normal
path -- the chain was alive and drawing to the screen.

This run stubs that prompt, so the chain continues past it.

Read the SCREEN:

  Samsung logo / Android / any boot UI -> the normal path runs past the
        prompt, and the LDFW initializer can be probed next
  a different prompt or error text -> say exactly what it shows
  black -> it stops right after the prompt; that is the next bit

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
