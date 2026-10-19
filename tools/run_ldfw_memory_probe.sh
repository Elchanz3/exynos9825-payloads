#!/usr/bin/env bash
# Run an LDFW diagnostic over the volatile USB path.
# The custom-key payload only redirects the BootROM key pointer in iRAM.  This
# script does not flash storage and the diagnostic u-boot issues no OTP command.

set -euo pipefail

REPO="/home/chanz22/Documents/GitHub/exynos9825-payloads"
EUB="/home/chanz22/EUB-N10"
CUSTOM="$EUB/9825_customkey"
HOUSTON="$REPO/../houston-pub"
PAYLOAD="$REPO/build/epbl_custom_key_efuse_probe.bin"

MODE="${1:-memory}"
case "$MODE" in
    memory)
        CHAIN="$REPO/build/ldfwmem_chain/sboot"
        IMAGE="$REPO/build/ldfwmem_chain/sboot.bin"
        OUT="/tmp/exynos9825_ldfw_memory_probe.bin"
        DESCRIPTION="post-init memory probe"
        READS="0x82001000 and 0x82001010 after CM/LDFW initialization"
        EXPECTED="LDFW p0=<word> p1=<word> ret=<value>"
        ;;
    mode)
        CHAIN="$REPO/build/ldfwmode_chain/sboot"
        IMAGE="$REPO/build/ldfwmode_chain/sboot.bin"
        OUT="/tmp/exynos9825_ldfw_mode_probe.bin"
        DESCRIPTION="CM/LDFW boot-mode gate probe"
        READS="0x80000000 and 0x80000010 before the CM/LDFW initializer"
        EXPECTED="LDFW m0=<word> m1=<word> ret=<value>"
        ;;
    *)
        echo "usage: $0 [memory|mode]" >&2
        exit 2
        ;;
esac

for path in \
    "$CHAIN/epbl.bin" \
    "$CHAIN/fwbl1.bin" \
    "$CHAIN/bl2.bin" \
    "$CHAIN/u-boot.bin" \
    "$CHAIN/el3_mon.bin"; do
    if [[ ! -f "$path" ]]; then
        echo "error: missing generated stage: $path" >&2
        echo "build the LDFW $MODE chain documented in docs/custom_key_fuse_port.md" >&2
        exit 1
    fi
done

echo "== building and checking the volatile custom-key payload =="
make -C "$REPO" build/epbl_custom_key_efuse_probe.bin
python3 "$REPO/tools/check_custom_key.py" "$PAYLOAD"
echo

echo "== verifying the diagnostic chain with the device-format verifier =="
(
    cd "$CUSTOM"
    KEYS_DIR="$CUSTOM/keys" \
        python3 scripts/verify_9825.py "$IMAGE"
)
echo

echo "== sudo authentication before the 6.5 second BootROM window =="
if sudo -n true 2>/dev/null; then
    echo "   already cached"
elif [[ -t 0 ]]; then
    sudo -v
else
    echo "error: run from a terminal so sudo can prompt before EUB mode" >&2
    exit 1
fi
echo

echo "== read-only LDFW $DESCRIPTION =="
echo "   reads: $READS"
echo "   expected console line: $EXPECTED"
echo "   EP1 console capture continues for 15 seconds after all stages are sent"
echo "   no flash and no OTP command"
echo "   output: $OUT"
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
