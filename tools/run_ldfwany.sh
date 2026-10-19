#!/usr/bin/env bash
# Stream the one-variable Secure Payload test and read the SCREEN, not EP1.
set -euo pipefail
REPO="/home/chanz22/Documents/GitHub/exynos9825-payloads"
HOUSTON="$REPO/../houston-pub"
PAYLOAD="$REPO/build/epbl_custom_key_efuse_probe.bin"
CHAIN="$REPO/build/ldfwany_chain/sboot"
OUT="/tmp/exynos9825_ldfwany.bin"

[[ -f "$CHAIN/u-boot.bin" ]] || {
    echo "error: build it first with tools/build_ldfwany_chain.sh" >&2
    exit 1
}
make -C "$REPO" build/epbl_custom_key_efuse_probe.bin
python3 "$REPO/tools/check_ldfw_observe_image.py" --ldfwany "$CHAIN/u-boot.bin"

cat <<EOF

Nothing is flashed and no OTP command exists in this image.

Last run moved the blue prompt onto the CM/LDFW SUCCESS path only, and went
black. That rules out success, but not "the initializer ran and took one of
the three failure paths" -- those still call printf, which draws nothing.

This run closes that gap: all four result paths draw the prompt.

Read the SCREEN:

  blue USB RECOVERY MODE  -> the initializer RAN. One of the four results was
        reached. The next run splits which one, and the fuse route is alive.
  black                   -> it never ran on this path either, the same as in
        Download mode. The chain dies before it, and the fuse needs the UFS
        route to work first.

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
