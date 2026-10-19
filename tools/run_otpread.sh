#!/usr/bin/env bash
# Stream the one-variable Secure Payload test and read the SCREEN, not EP1.
set -euo pipefail
REPO="/home/chanz22/Documents/GitHub/exynos9825-payloads"
HOUSTON="$REPO/../houston-pub"
PAYLOAD="$REPO/build/epbl_custom_key_efuse_probe.bin"
CHAIN="$REPO/build/otpread_chain/sboot"
OUT="/tmp/exynos9825_otpread.bin"

[[ -f "$CHAIN/u-boot.bin" ]] || {
    echo "error: build it first with tools/build_otpread_chain.sh" >&2
    exit 1
}
make -C "$REPO" build/epbl_custom_key_efuse_probe.bin
python3 "$REPO/tools/check_ldfw_observe_image.py" --otpread "$CHAIN/u-boot.bin"

cat <<EOF

The CM partition now holds our re-signed cm.bin and the CM/LDFW initializer
succeeds. The question is no longer whether the chain runs -- it is whether
the secure side will answer an OTP command at all.

This image asks with a READ, never a write:

    0xc90a2c94  USE_ROM_SEC_BOOT_KEY2 read
                smc(0xc2001014, 0x115, 0, 0)

The build refuses unless the trampoline calls exactly that function and not
the programming one. Command 0x16 is not reachable from any path here.

Read the SCREEN:

  blue USB RECOVERY MODE -> the SMC returned 0 and the value was read. The
        OTP service is live.
  black                  -> it still answers -1 or an error; the next marker
        separates "LDFW not loaded" from "read failed".

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
