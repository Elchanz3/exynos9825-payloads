#!/usr/bin/env bash
# Stream the one-variable Secure Payload test and read the SCREEN, not EP1.
set -euo pipefail
REPO="/home/chanz22/Documents/GitHub/exynos9825-payloads"
HOUSTON="$REPO/../houston-pub"
PAYLOAD="$REPO/build/epbl_custom_key_efuse_probe.bin"
CHAIN="$REPO/build/otpcheck_chain/sboot"
OUT="/tmp/exynos9825_otpcheck.bin"

[[ -f "$CHAIN/u-boot.bin" ]] || {
    echo "error: build it first with tools/build_otpcheck_chain.sh" >&2
    exit 1
}
make -C "$REPO" build/epbl_custom_key_efuse_probe.bin
python3 "$REPO/tools/check_ldfw_observe_image.py" --otpcheck "$CHAIN/u-boot.bin"

cat <<EOF

The OTP service answered the read 0x115, so it is live. This run rehearses
the BUFFER path -- the one the irreversible command uses -- with the
comparison command, which never writes:

    0xc90a299c  ROM_SECURE_BOOT_KEY2 check
                x0 = our 32-byte anchor, w1 = 0x20
                smc(0xc2001014, 0x114, ...)
                -> "check: valid key"
                -> "check: invalid key"
                -> "hasn't been programed yet"      <- wired to the prompt

The build refuses unless the callee is the check function and not the
programming one. The answer does not depend on which bytes are passed, so
the anchor is there only to make the rehearsal faithful.

Read the SCREEN:

  blue USB RECOVERY MODE -> the device's own service reports KEY2 blank, over
        exactly the path 0x16 would use. Everything before the fuse is then
        proven on hardware.
  black                  -> it answered "valid" or "invalid" instead, which
        would be surprising and worth stopping on.

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
