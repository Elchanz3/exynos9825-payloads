#!/usr/bin/env bash
set -euo pipefail
REPO="/home/chanz22/Documents/GitHub/exynos9825-payloads"
HOUSTON="$REPO/../houston-pub"
PAYLOAD="$REPO/build/epbl_custom_key_efuse_probe.bin"
CHAIN="$REPO/build/prompt_probe_chain/sboot"
[[ -f "$CHAIN/u-boot.bin" ]] || { echo "build it first" >&2; exit 1; }
make -C "$REPO" build/epbl_custom_key_efuse_probe.bin
cat <<EOF

Nothing is flashed and no OTP command exists in this image.

  blue USB RECOVERY MODE -> the marked code was REACHED
  anything else          -> it was not

EOF
if sudo -n true 2>/dev/null; then echo "   sudo cached"; elif [[ -t 0 ]]; then sudo -v; else exit 1; fi
echo; echo "Wait for 'Waiting for EUB 04e8:1234...', then enter EUB mode."; echo
exec sudo "$HOUSTON/.venv/bin/python3" "$REPO/tools/boot_nonsecure_probe.py" \
    --houston-dir "$HOUSTON" --payload "$PAYLOAD" --allow-unpinned-stages \
    --receive-test \
    --receive-file "$CHAIN/epbl.bin" \
    --receive-next-file "$CHAIN/fwbl1.bin" \
    --receive-next-file "$CHAIN/bl2.bin" \
    --receive-next-file "$CHAIN/u-boot.bin" \
    --receive-next-file "$CHAIN/el3_mon.bin" \
    --output "/tmp/exynos9825_prompt_probe.bin"
