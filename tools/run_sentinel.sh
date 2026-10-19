#!/usr/bin/env bash
# Stream the one-variable Secure Payload test and read the SCREEN, not EP1.
set -euo pipefail
REPO="/home/chanz22/Documents/GitHub/exynos9825-payloads"
HOUSTON="$REPO/../houston-pub"
PAYLOAD="$REPO/build/epbl_custom_key_efuse_probe.bin"
CHAIN="$REPO/build/sentinel_chain/sboot"
OUT="/tmp/exynos9825_sentinel.bin"

[[ -f "$CHAIN/u-boot.bin" ]] || {
    echo "error: build it first with tools/build_sentinel_chain.sh" >&2
    exit 1
}
make -C "$REPO" build/epbl_custom_key_efuse_probe.bin
python3 "$REPO/tools/check_ldfw_observe_image.py" --ldfwany "$CHAIN/u-boot.bin"

cat <<EOF

Nothing is flashed and no OTP command exists in this image.
The UFS content does not matter for this run; stock is fine and recommended.

A second model spotted the gate every previous LDFW result was hitting, and
it checks out instruction by instruction:

  0xc90033f4  str w2,[x20,#648]   ; 0xfa11, before asking for the Secure OS
  0xc9003500  str wzr,[x20,#648]  ; cleared only when that SMC returns 0
  0xc90a6254  ldr w1,[x0,#648]    ; the CM/LDFW initializer reads it first
  0xc90a6260  b.eq -> "[ldfw] Skip ldfw & Security initialize.
                       Secure Payload was not loaded."  ; ret -1

So the initializer does run -- it just leaves through a fifth exit that none
of the four instrumented results cover. Every black screen in the LDFW runs
is explained by this one gate.

This run makes it read 0 instead, so the initializer takes its real path,
and all four result diagnostics draw the blue prompt.

Read the SCREEN:

  blue USB RECOVERY MODE -> we are past the gate and one of the four real
        results was reached. The next run splits which, and that is the fact
        the fuse route needs.
  black                  -> the initializer dies inside, before any result.

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
