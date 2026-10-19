#!/usr/bin/env bash
# Stream the one-variable Secure Payload test and read the SCREEN, not EP1.
set -euo pipefail
REPO="/home/chanz22/Documents/GitHub/exynos9825-payloads"
HOUSTON="$REPO/../houston-pub"
PAYLOAD="$REPO/build/epbl_custom_key_efuse_probe.bin"
CHAIN="$REPO/build/ldfwok_chain/sboot"
OUT="/tmp/exynos9825_ldfwok.bin"

[[ -f "$CHAIN/u-boot.bin" ]] || {
    echo "error: build it first with tools/build_ldfwok_chain.sh" >&2
    exit 1
}
make -C "$REPO" build/epbl_custom_key_efuse_probe.bin
python3 "$REPO/tools/check_ldfw_observe_image.py" --ldfwsignal "$CHAIN/u-boot.bin"

cat <<EOF

Nothing is flashed and no OTP command exists in this image.
The UFS content does not matter; stock is fine.

The last run drew blue with all four CM/LDFW results wired to the prompt, so
the sentinel bypass works and the initializer reached one of its four real
outcomes. It also voids the earlier success-path run, which went black only
because the gate was still closing the initializer down early.

This run wires ONLY the success diagnostic to the prompt:

    "ldfw: try to init %d ldfw(s). except %d ldfw %d ldfw(s) have been
     inited done."

Read the SCREEN:

  blue USB RECOVERY MODE -> the CM/LDFW initializer SUCCEEDED. That is the
        precondition the whole fuse route has been blocked on. Next step is
        the read-only OTP command 0x114, not the irreversible one.
  black                  -> it took one of the three failure paths; the next
        run splits which, and the failure text tells us what is missing.

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
