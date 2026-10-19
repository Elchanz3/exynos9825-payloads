#!/usr/bin/env bash
# Program the derived custom-key trust anchor into the Exynos9825 KEY2 OTP slot.
# This workflow prepares a manual BOOTLOADER partition write and performs an
# irreversible OTP write. It does not set USE_KEY2; activation is separate.

set -euo pipefail

REPO="/home/chanz22/Documents/GitHub/exynos9825-payloads"
CUSTOM="/home/chanz22/EUB-N10/9825_customkey"
CHAIN="$REPO/build/key2_program_chain"
IMAGE="$CHAIN/sboot.bin"
ACTION="${1:-}"

usage() {
    cat >&2 <<EOF
usage: $0 {build|check|flash|trigger|trace|verify}

  build    regenerate and validate the KEY2-only chain from the stock image
  check    validate the KEY2-only stub and every chain signature
  flash    enter Download mode and print the manual BOOTLOADER flash command
  trigger  boot that UFS chain through EUB; this performs the irreversible OTP write
  trace    read the best-effort PMU checkpoints left by trigger
  verify   read both OTP slots and compare all 32 KEY2 bytes with the signer
EOF
    exit 2
}

check_chain() {
    python3 "$REPO/tools/check_key2_fuse_image.py" program "$CHAIN"
    (
        cd "$CUSTOM"
        python3 scripts/verify_9825.py "$IMAGE"
    )
}

wait_for_eub_disconnect() {
    if ! command -v lsusb >/dev/null; then
        return
    fi
    echo
    echo "Waiting for the completed EUB session to leave USB before the selector read..."
    while lsusb -d 04e8:1234 | grep -q .; do
        sleep 0.1
    done
    echo "Previous EUB session closed. The next probe will wait for a fresh entry."
    echo
}

case "$ACTION" in
    build)
        "$REPO/tools/build_key2_fuse_chain.sh" program
        ;;
    check)
        check_chain
        ;;
    flash)
        check_chain
        command -v odin >/dev/null || {
            echo "error: odin/heimdall is not installed" >&2
            exit 1
        }
        cat <<EOF

The following image must later be written to exactly one UFS partition:
  partition: BOOTLOADER (sboot)
  image:     $IMAGE

The chain programs KEY2 when it is subsequently booted through UFS.
It does not set USE_KEY2.

First enter EUB when the USB loader asks. The engineering chain will leave the
board in Samsung Download mode. This script does not start Odin automatically.

Wait until the Download/Odin screen reaches 100%. Only then run the exact
manual command printed after the engineering loader exits.
EOF
        # The engineering loader normally loses its EP1 handle when u-boot
        # re-enumerates as Samsung Download mode.  Its helper reports that
        # expected disconnect as a non-zero exit, so do not let `set -e`
        # suppress the manual-flash instructions. Preserve interruption.
        set +e
        "$CUSTOM/run_custom_key_test.sh" efuse ecdsa_eng
        loader_rc=$?
        set -e
        case "$loader_rc" in
            0)
                ;;
            130|143)
                exit "$loader_rc"
                ;;
            *)
                echo "Engineering loader exited with status $loader_rc; continuing because Download-mode USB re-enumeration closes its EUB handle." >&2
                ;;
        esac
        cat <<EOF

Samsung Download mode should now be starting.

Do not run Odin until the Download/Odin screen reaches 100% and the device is
fully ready.

BOOTLOADER image:
  $IMAGE

When the screen reaches 100%, run this command manually:

  sudo odin flash --BOOTLOADER $IMAGE

This script has not written the BOOTLOADER partition.
EOF
        ;;
    trigger)
        check_chain
        cat <<EOF

This is the irreversible step. Enter EUB when requested. The payload redirects
BootROM verification to the custom key, loads the flashed chain from UFS, and
hands off without accessing untrained DRAM. The patched u-boot neutralizes the
three stale EUB mode reads after BL2 has initialized memory. Exactly one of the
four CM/LDFW initializer result paths then calls OTP command 0x16 to program
KEY2; the later uH loader call remains as a fallback.

BOOTLOADER image expected on UFS:
  $IMAGE

This trigger does not rewrite UFS. If the image above is already flashed, do
not run Odin again for this diagnostic revision; only the RAM payload changed.

The preceding hardware run reached UFWMAIN!. Static analysis confirms that
site is the final branch into FWBL1's context restore and ERET, immediately
before BL2. The missing intermediate records were dropped EP1 transfers, not
evidence that their initialization calls failed.

The saved-ELR transition test also returned neither UBL2ENT! nor UBL2MISS.
Because its only late transfer ran after ERET, that result is consistent with
EP1 or the BootROM USB helper no longer being usable in the restored context.

UBL2PRE! proved that the hook ran, but its zero ELR/SPSR/SCR fields exposed a
stack-selection mistake in that diagnostic. The stock code first saves the
current SP, switches SPSel to 1, and then reads the frame through SP_EL3. The
reported 0x02033780 was the pre-switch SP, not the frame base.

This revision reads the frame through SP_EL3 and also reports the current SP
and SPSel. It still does not modify BL2 or any saved context field. After the
bounded record attempt it branches directly to the original restore at
0x0202a9d4, so the normal chain can continue into BL2 and the already-flashed
u-boot OTP path.

This revision makes no USB transfer during FWBL1 initialization. It reports:
  UFSLOAD!  BootROM loaded the UFS EPBL; this transfer completes before reuse
  UFSMETA!  the loaded EPBL metadata; this transfer also completes before reuse
  UBL2CTX!  saved ELR/SPSR/SCR from SP_EL3, both SP values, target word, SPSel

UBL2CTX! is the only late bounded transfer and its DMA buffer is never reused.
The saved frame and persistent BOOTLOADER image remain unchanged; do not run
Odin for this diagnostic revision.
EOF
        "$CUSTOM/run_boot_ufs_chain_test.sh"
        ;;
    trace)
        payload="$REPO/build/epbl_pmu_trace_probe.bin"
        output="/tmp/exynos9825_pmu_trace.bin"
        houston="$REPO/../houston-pub"
        make -C "$REPO" build/epbl_pmu_trace_probe.bin
        if sudo -n true 2>/dev/null; then
            :
        elif [[ -t 0 ]]; then
            sudo -v
        else
            echo "error: sudo authentication requires a real terminal" >&2
            exit 1
        fi
        cat <<EOF

Read-only best-effort PMU checkpoint recovery.

Enter EUB only after 'Waiting for EUB 04e8:1234...' appears. The result shows
any retained checkpoints from the preceding trigger. An all-zero result is
inconclusive because retention across EUB reentry has not been proven. The
trigger's live UFSLOAD/UFSMETA/UBL2CTX records are authoritative when present.
EOF
        sudo "$houston/.venv/bin/python3" "$REPO/tools/boot_nonsecure_probe.py" \
            --houston-dir "$houston" \
            --payload "$payload" \
            --output "$output"
        ;;
    verify)
        cat <<EOF

Verification uses two fresh EUB sessions:
  1. dump all 32 bytes of KEY and KEY2;
  2. after the first USB session closes, read the selector state.

The script waits for the old device to disappear before starting step 2.
If the first dump is valid but KEY2 does not match, step 2 still runs before
the command returns a failure status.
EOF
        expected="$({
            cd "$CUSTOM"
            python3 -c "import sys;sys.path.insert(0,'scripts');import patch_9825 as p;print(p.get_efuse_data().hex())"
        })"
        payload="$REPO/build/epbl_key_dump_probe.bin"
        output="/tmp/exynos9825_key_dump.bin"
        houston="$REPO/../houston-pub"
        rm -f "$output"
        make -C "$REPO" build/epbl_key_dump_probe.bin
        if sudo -n true 2>/dev/null; then
            :
        elif [[ -t 0 ]]; then
            sudo -v
        else
            echo "error: sudo authentication requires a real terminal" >&2
            exit 1
        fi
        set +e
        sudo env EXPECT_KEY2="$expected" \
            "$houston/.venv/bin/python3" "$REPO/tools/boot_nonsecure_probe.py" \
            --houston-dir "$houston" \
            --payload "$payload" \
            --output "$output"
        dump_rc=$?
        set -e
        case "$dump_rc" in
            130|143)
                exit "$dump_rc"
                ;;
        esac
        dump_record_valid=0
        if [[ -f "$output" ]] && python3 - "$output" <<'PY'
import struct
import sys

data = open(sys.argv[1], "rb").read()
valid = (
    len(data) >= 0x60
    and data[:8] == b"KEXDUM!!"
    and struct.unpack_from("<II", data, 8) == (1, 0x60)
)
raise SystemExit(0 if valid else 1)
PY
        then
            dump_record_valid=1
        fi
        if ((dump_rc != 0 && dump_record_valid == 0)); then
            exit 1
        fi
        wait_for_eub_disconnect
        set +e
        "$CUSTOM/run_key_state_test.sh"
        state_rc=$?
        set -e
        if ((state_rc != 0)); then
            exit 1
        fi
        if ((dump_rc != 0)); then
            exit "$dump_rc"
        fi
        ;;
    *)
        usage
        ;;
esac
