#!/usr/bin/env bash
# Prove that BL2 enters the custom-signed full u-boot slot loaded from UFS.

set -euo pipefail

REPO="/home/chanz22/Documents/GitHub/exynos9825-payloads"
CUSTOM="/home/chanz22/EUB-N10/9825_customkey"
HOUSTON="$REPO/../houston-pub"
CHAIN="$REPO/build/ubstage_test_chain"
IMAGE="$CHAIN/sboot.bin"
CONTROL_IMAGE="$CUSTOM/ecdsa_eng/sboot.bin"
CONTROL_SLOT="$CUSTOM/ecdsa_eng/sboot/u-boot.bin"
FORCED_CHAIN="$REPO/build/ubstage_forced_download_chain"
FORCED_IMAGE="$FORCED_CHAIN/sboot.bin"
FORCED_BASE="$FORCED_CHAIN/u-boot.base.bin"
FORCED_SLOT="$FORCED_CHAIN/sboot/u-boot.bin"
PAYLOAD="$REPO/build/epbl_boot_ufs_plain_probe.bin"
SILENT_PAYLOAD="$REPO/build/epbl_boot_ufs_silent_probe.bin"
NATIVE_PAYLOAD="$REPO/build/epbl_boot_ufs_native_probe.bin"
NATIVE_ELF="$REPO/build/epbl_boot_ufs_native_probe.elf"
NATIVE_LOAD_DIAG_PAYLOAD="$REPO/build/epbl_boot_ufs_native_load_diag_probe.bin"
NATIVE_LOAD_DIAG_ELF="$REPO/build/epbl_boot_ufs_native_load_diag_probe.elf"
NATIVE_POSTLOAD_DIAG_PAYLOAD="$REPO/build/epbl_boot_ufs_native_postload_diag_probe.bin"
NATIVE_POSTLOAD_DIAG_ELF="$REPO/build/epbl_boot_ufs_native_postload_diag_probe.elf"
NATIVE_TIMING_DIAG_PAYLOAD="$REPO/build/epbl_boot_ufs_native_timing_diag_probe.bin"
NATIVE_TIMING_DIAG_ELF="$REPO/build/epbl_boot_ufs_native_timing_diag_probe.elf"
NATIVE_FLAG_DIAG_PAYLOAD="$REPO/build/epbl_boot_ufs_native_flag_diag_probe.bin"
NATIVE_FLAG_DIAG_ELF="$REPO/build/epbl_boot_ufs_native_flag_diag_probe.elf"
NATIVE_COLD_DIAG_PAYLOAD="$REPO/build/epbl_boot_ufs_native_cold_diag_probe.bin"
NATIVE_COLD_DIAG_ELF="$REPO/build/epbl_boot_ufs_native_cold_diag_probe.elf"
NATIVE_FORCE_COLD_PAYLOAD="$REPO/build/epbl_boot_ufs_native_force_cold_probe.bin"
NATIVE_FORCE_COLD_ELF="$REPO/build/epbl_boot_ufs_native_force_cold_probe.elf"
NATIVE_TRIPLE_PAYLOAD="$REPO/build/epbl_boot_ufs_native_triple_probe.bin"
NATIVE_TRIPLE_ELF="$REPO/build/epbl_boot_ufs_native_triple_probe.elf"
KEYSAFE_PAYLOAD="$REPO/build/epbl_boot_ufs_native_keysafe_probe.bin"
KEYSAFE_ELF="$REPO/build/epbl_boot_ufs_native_keysafe_probe.elf"
STOCKKEY_PAYLOAD="$REPO/build/epbl_boot_ufs_native_stockkey_probe.bin"
STOCKKEY_ELF="$REPO/build/epbl_boot_ufs_native_stockkey_probe.elf"
NATIVE_TRIPLE_STOCK_PAYLOAD="$REPO/build/epbl_boot_ufs_native_triple_stock_probe.bin"
NATIVE_TRIPLE_STOCK_ELF="$REPO/build/epbl_boot_ufs_native_triple_stock_probe.elf"
NATIVE_TRIPLE_RESTORE_PAYLOAD="$REPO/build/epbl_boot_ufs_native_triple_restore_probe.bin"
NATIVE_TRIPLE_RESTORE_ELF="$REPO/build/epbl_boot_ufs_native_triple_restore_probe.elf"
STOCK_SBOOT="$CUSTOM/input/sboot.bin"
STOCK_EPBL="$REPO/build/stock_epbl.bin"
NATIVE_DIAG_PAYLOAD="$REPO/build/epbl_boot_ufs_native_diag_probe.bin"
NATIVE_DIAG_ELF="$REPO/build/epbl_boot_ufs_native_diag_probe.elf"
OUTPUT="/tmp/exynos9825_ubstage_test.bin"
ACTION="${1:-}"

usage() {
    cat >&2 <<EOF
usage: $0 {build|check|flash|trigger|control-check|control-flash|control-trigger|silent-trigger|force-download-check|force-download-flash|force-download-trigger|native-check|native-trigger|native-load-diagnose|native-postload-diagnose|native-timing-diagnose|native-flag-diagnose|native-cold-diagnose|native-force-cold|native-triple|native-keysafe|native-stockkey|native-triple-stock|native-triple-restore|native-diagnose|trace|calibrate-retention}

  build    regenerate the signed entry-test chain from the stock image
  check    validate its replacement stage and every chain signature
  flash    enter Download mode and print the manual BOOTLOADER flash command
  trigger  boot the flashed test chain through the legacy FWBL1 shim
  control-check
           validate the exact uninstrumented ecdsa_eng control image
  control-flash
           enter Download mode and print the manual uninstrumented-control command
  control-trigger
           boot the exact ecdsa_eng control image through the legacy FWBL1 shim
  silent-trigger
           repeat that control without any post-load EP1 IN transfer
  force-download-check
           validate the signed u-boot that forces Download reason 4
  force-download-flash
           enter Download mode and print its manual BOOTLOADER flash command
  force-download-trigger
           boot that image through the legacy silent FWBL1 shim
  native-check
           validate the unhooked EPBL/FWBL1 handoff payload
  native-trigger
           boot the forced-Download image through the native UFS handoff
  native-load-diagnose
           report immediately after the native BootROM UFS load returns
  native-postload-diagnose
           report immediately after native BL1 verification returns
  native-timing-diagnose
           report after the final entry-timing helper and before the boot flag
  native-flag-diagnose
           report after the final boot-flag helper and before entry validation
  native-cold-diagnose
           report the EPBL warm gate, force its verified cold branch and boot
  native-force-cold
           skip the warm-state MMIO and enter the verified native cold loader
  native-triple-stock
           STOCK sboot on UFS: emit one read-only record at three positions
  native-triple-restore
           put the BootROM's own key pointer back after the verifier returns
  native-triple [eng|forced]
           same measurement with the custom key redirect; eng is the default
           and is the image already proven over USB
  native-diagnose
           snapshot the native EPBL entry state and catch an EPBL return
  trace    explain why the former cross-EUB PMU trace is retired
  calibrate-retention
           write volatile PMU/iRAM markers, then read them in a fresh EUB
EOF
    exit 2
}

check_control_chain() {
    [[ -f "$CONTROL_IMAGE" && -f "$CONTROL_SLOT" ]] || {
        echo "error: missing the uninstrumented ecdsa_eng control chain" >&2
        exit 1
    }
    python3 - "$CONTROL_SLOT" <<'PY'
import hashlib
import struct
import sys
from pathlib import Path

slot_path = Path(sys.argv[1])
slot = slot_path.read_bytes()
CAVE = 0x17CE00

if len(slot) != 0x180000:
    raise SystemExit("error: unexpected control u-boot slot size")
if struct.unpack_from("<I", slot, 0)[0] != 0x14000001:
    raise SystemExit("error: control u-boot no longer has its original entry")
if slot[0x4FC68:0x4FC70] != bytes.fromhex("00 00 80 d2 c0 03 5f d6"):
    raise SystemExit("error: control u-boot contains an OTP-capable signature stub")
if any(slot[CAVE:CAVE + 0x80]):
    raise SystemExit("error: control u-boot marker cave is not empty")

print(f"uninstrumented u-boot control = PASS ({hashlib.sha256(slot).hexdigest()})")
print("entry trampoline = ABSENT")
print("OTP command injection = ABSENT")
PY
    (
        cd "$CUSTOM"
        python3 scripts/verify_9825.py "$CONTROL_IMAGE"
    )
    echo "control sboot sha256 $(sha256sum "$CONTROL_IMAGE" | awk '{print $1}')"
}

check_chain() {
    [[ -f "$IMAGE" ]] || {
        echo "error: missing $IMAGE; run '$0 build' first" >&2
        exit 1
    }
    make -C "$REPO" build/ubstage_download_marker.bin
    python3 - \
        "$REPO/build/ubstage_download_marker.bin" \
        "$CHAIN/u-boot.base.bin" \
        "$CHAIN/sboot/u-boot.bin" \
        "$CUSTOM/ecdsa_eng/sboot/u-boot.bin" <<'PY'
import hashlib
import struct
import sys
from pathlib import Path

stage = Path(sys.argv[1]).read_bytes()
base = Path(sys.argv[2]).read_bytes()
slot = Path(sys.argv[3]).read_bytes()
proven = Path(sys.argv[4]).read_bytes()
footer = len(slot) - 0x210
CAVE = 0x17CE00
LOAD = 0xC9000000

def u32(data, offset):
    return struct.unpack_from("<I", data, offset)[0]

def resolve_b(value, address):
    if value & 0xFC000000 != 0x14000000:
        raise SystemExit(f"error: {address:#x} is not an unconditional branch")
    imm = value & 0x03FFFFFF
    if imm & (1 << 25):
        imm -= 1 << 26
    return address + imm * 4

if len(base) != 0x180000 or len(slot) != len(base):
    raise SystemExit("error: unexpected u-boot slot size")
if len(proven) != len(base) or proven[:footer] != base[:footer]:
    raise SystemExit("error: diagnostic base differs from the proven ecdsa_eng body")
if base[0x4FC68:0x4FC70] != bytes.fromhex("00 00 80 d2 c0 03 5f d6"):
    raise SystemExit("error: diagnostic contains an OTP-capable signature stub")
if resolve_b(u32(slot, 0), LOAD) != LOAD + CAVE:
    raise SystemExit("error: u-boot entry marker branch is missing")
if slot[CAVE:CAVE + len(stage) - 4] != stage[:-4]:
    raise SystemExit("error: u-boot entry marker body does not match")
resume_at = LOAD + CAVE + len(stage) - 4
if resolve_b(u32(slot, CAVE + len(stage) - 4), resume_at) != LOAD + 4:
    raise SystemExit("error: u-boot marker does not resume at load+4")

allowed = set(range(4))
allowed.update(range(CAVE, CAVE + len(stage)))
allowed.update(range(footer, len(slot)))
unexpected = [i for i, (a, b) in enumerate(zip(base, slot))
              if a != b and i not in allowed]
if unexpected:
    raise SystemExit(f"error: unexpected u-boot change at {unexpected[0]:#x}")

print(f"full u-boot Download reporter = PASS ({hashlib.sha256(stage).hexdigest()})")
print("base body matches proven ecdsa_eng = YES")
print("OTP command injection = ABSENT")
PY
    (
        cd "$CUSTOM"
        python3 scripts/verify_9825.py "$IMAGE"
    )
    echo "diagnostic sboot sha256 $(sha256sum "$IMAGE" | awk '{print $1}')"
}

check_forced_download_chain() {
    [[ -f "$FORCED_IMAGE" && -f "$FORCED_BASE" && -f "$FORCED_SLOT" ]] || {
        echo "error: missing the forced-Download chain; run '$REPO/tools/build_ubstage_forced_download_chain.sh' first" >&2
        exit 1
    }
    python3 "$REPO/tools/check_ubstage_forced_download.py" \
        "$FORCED_BASE" "$FORCED_SLOT" "$CONTROL_SLOT"
    (
        cd "$CUSTOM"
        python3 scripts/verify_9825.py "$FORCED_IMAGE"
    )
    echo "forced-Download sboot sha256 $(sha256sum "$FORCED_IMAGE" | awk '{print $1}')"
}

check_native_payload() {
    make -C "$REPO" build/epbl_boot_ufs_native_probe.bin
    python3 "$REPO/tools/check_native_ufs_payload.py" \
        "$NATIVE_ELF" \
        "$NATIVE_PAYLOAD" \
        "$FORCED_CHAIN/sboot/epbl.bin"
    python3 "$REPO/tools/check_custom_key.py" \
        "$NATIVE_PAYLOAD" --candidate efuse
    echo "native payload sha256 $(sha256sum "$NATIVE_PAYLOAD" | awk '{print $1}')"
}

check_native_diagnostic_payload() {
    make -C "$REPO" build/epbl_boot_ufs_native_diag_probe.bin
    python3 "$REPO/tools/check_native_ufs_payload.py" \
        --diagnostic \
        "$NATIVE_DIAG_ELF" \
        "$NATIVE_DIAG_PAYLOAD" \
        "$FORCED_CHAIN/sboot/epbl.bin"
    python3 "$REPO/tools/check_custom_key.py" \
        "$NATIVE_DIAG_PAYLOAD" --candidate efuse
    echo "native diagnostic payload sha256 $(sha256sum "$NATIVE_DIAG_PAYLOAD" | awk '{print $1}')"
}

check_native_load_diagnostic_payload() {
    make -C "$REPO" build/epbl_boot_ufs_native_load_diag_probe.bin
    python3 "$REPO/tools/check_native_ufs_payload.py" \
        --post-load-records \
        "$NATIVE_LOAD_DIAG_ELF" \
        "$NATIVE_LOAD_DIAG_PAYLOAD" \
        "$FORCED_CHAIN/sboot/epbl.bin"
    python3 "$REPO/tools/check_custom_key.py" \
        "$NATIVE_LOAD_DIAG_PAYLOAD" --candidate efuse
    echo "native post-load diagnostic sha256 $(sha256sum "$NATIVE_LOAD_DIAG_PAYLOAD" | awk '{print $1}')"
}

check_native_postload_diagnostic_payload() {
    make -C "$REPO" build/epbl_boot_ufs_native_postload_diag_probe.bin
    python3 "$REPO/tools/check_native_ufs_payload.py" \
        --postload-result-record \
        "$NATIVE_POSTLOAD_DIAG_ELF" \
        "$NATIVE_POSTLOAD_DIAG_PAYLOAD" \
        "$FORCED_CHAIN/sboot/epbl.bin"
    python3 "$REPO/tools/check_custom_key.py" \
        "$NATIVE_POSTLOAD_DIAG_PAYLOAD" --candidate efuse
    echo "native postload diagnostic sha256 $(sha256sum "$NATIVE_POSTLOAD_DIAG_PAYLOAD" | awk '{print $1}')"
}

check_native_timing_diagnostic_payload() {
    make -C "$REPO" build/epbl_boot_ufs_native_timing_diag_probe.bin
    python3 "$REPO/tools/check_native_ufs_payload.py" \
        --timing-result-record \
        "$NATIVE_TIMING_DIAG_ELF" \
        "$NATIVE_TIMING_DIAG_PAYLOAD" \
        "$FORCED_CHAIN/sboot/epbl.bin"
    python3 "$REPO/tools/check_custom_key.py" \
        "$NATIVE_TIMING_DIAG_PAYLOAD" --candidate efuse
    echo "native timing diagnostic sha256 $(sha256sum "$NATIVE_TIMING_DIAG_PAYLOAD" | awk '{print $1}')"
}

check_native_flag_diagnostic_payload() {
    make -C "$REPO" build/epbl_boot_ufs_native_flag_diag_probe.bin
    python3 "$REPO/tools/check_native_ufs_payload.py" \
        --flag-result-record \
        "$NATIVE_FLAG_DIAG_ELF" \
        "$NATIVE_FLAG_DIAG_PAYLOAD" \
        "$FORCED_CHAIN/sboot/epbl.bin"
    python3 "$REPO/tools/check_custom_key.py" \
        "$NATIVE_FLAG_DIAG_PAYLOAD" --candidate efuse
    echo "native boot-flag diagnostic sha256 $(sha256sum "$NATIVE_FLAG_DIAG_PAYLOAD" | awk '{print $1}')"
}

check_native_cold_diagnostic_payload() {
    make -C "$REPO" build/epbl_boot_ufs_native_cold_diag_probe.bin
    python3 "$REPO/tools/check_native_ufs_payload.py" \
        --cold-result-record \
        "$NATIVE_COLD_DIAG_ELF" \
        "$NATIVE_COLD_DIAG_PAYLOAD" \
        "$FORCED_CHAIN/sboot/epbl.bin"
    python3 "$REPO/tools/check_custom_key.py" \
        "$NATIVE_COLD_DIAG_PAYLOAD" --candidate efuse
    echo "native cold-path diagnostic sha256 $(sha256sum "$NATIVE_COLD_DIAG_PAYLOAD" | awk '{print $1}')"
}

check_native_force_cold_payload() {
    make -C "$REPO" build/epbl_boot_ufs_native_force_cold_probe.bin
    python3 "$REPO/tools/check_native_ufs_payload.py" \
        --force-cold-record \
        "$NATIVE_FORCE_COLD_ELF" \
        "$NATIVE_FORCE_COLD_PAYLOAD" \
        "$FORCED_CHAIN/sboot/epbl.bin"
    python3 "$REPO/tools/check_custom_key.py" \
        "$NATIVE_FORCE_COLD_PAYLOAD" --candidate efuse
    echo "native force-cold payload sha256 $(sha256sum "$NATIVE_FORCE_COLD_PAYLOAD" | awk '{print $1}')"
}

check_native_triple_payload() {
    local epbl="${1:-$FORCED_CHAIN/sboot/epbl.bin}"
    make -C "$REPO" build/epbl_boot_ufs_native_triple_probe.bin
    python3 "$REPO/tools/check_native_ufs_payload.py" \
        --triple-records \
        "$NATIVE_TRIPLE_ELF" \
        "$NATIVE_TRIPLE_PAYLOAD" \
        "$epbl"
    python3 "$REPO/tools/check_custom_key.py" \
        "$NATIVE_TRIPLE_PAYLOAD" --candidate efuse
    echo "native triple payload sha256 $(sha256sum "$NATIVE_TRIPLE_PAYLOAD" | awk '{print $1}')"
}

check_native_triple_stock_payload() {
    if [[ ! -f "$STOCK_SBOOT" ]]; then
        echo "error: stock sboot is missing: $STOCK_SBOOT" >&2
        exit 1
    fi
    # The EPBL is the first 0x3000 bytes of sboot. It is byte-identical to the
    # one in every resigned chain except the cleared header checksum and the
    # ST1/ST2 signature, neither of which this payload reads.
    head -c 12288 "$STOCK_SBOOT" > "$STOCK_EPBL"
    make -C "$REPO" build/epbl_boot_ufs_native_triple_stock_probe.bin
    python3 "$REPO/tools/check_native_ufs_payload.py" \
        --triple-records --no-custom-key \
        "$NATIVE_TRIPLE_STOCK_ELF" \
        "$NATIVE_TRIPLE_STOCK_PAYLOAD" \
        "$STOCK_EPBL"
    echo "native triple stock payload sha256 $(sha256sum "$NATIVE_TRIPLE_STOCK_PAYLOAD" | awk '{print $1}')"
}

check_native_triple_restore_payload() {
    local epbl="${1:-$CUSTOM/ecdsa_eng/sboot/epbl.bin}"
    make -C "$REPO" build/epbl_boot_ufs_native_triple_restore_probe.bin
    python3 "$REPO/tools/check_native_ufs_payload.py" \
        --triple-records \
        "$NATIVE_TRIPLE_RESTORE_ELF" \
        "$NATIVE_TRIPLE_RESTORE_PAYLOAD" \
        "$epbl"
    python3 "$REPO/tools/check_custom_key.py" \
        "$NATIVE_TRIPLE_RESTORE_PAYLOAD" --candidate efuse
    echo "native triple restore payload sha256 $(sha256sum "$NATIVE_TRIPLE_RESTORE_PAYLOAD" | awk '{print $1}')"
}

authenticate_sudo() {
    if sudo -n true 2>/dev/null; then
        echo "   already cached, nothing to do"
    elif [[ -t 0 ]]; then
        sudo -v
    else
        echo "error: sudo authentication requires a real terminal" >&2
        exit 1
    fi
}

wait_for_eub_disconnect() {
    if ! command -v lsusb >/dev/null; then
        return
    fi
    echo
    echo "Waiting for the completed marker session to leave USB..."
    while lsusb -d 04e8:1234 | grep -q .; do
        sleep 0.1
    done
    echo "Previous EUB session closed. The reader now requires a fresh entry."
    echo
}

case "$ACTION" in
    build)
        "$REPO/tools/build_ubstage_test_chain.sh"
        ;;
    check)
        check_chain
        ;;
    control-check)
        check_control_chain
        ;;
    force-download-check)
        check_forced_download_chain
        ;;
    native-check)
        check_forced_download_chain
        check_native_payload
        ;;
    flash)
        check_chain
        command -v odin >/dev/null || {
            echo "error: odin/heimdall is not installed" >&2
            exit 1
        }
        cat <<EOF

This diagnostic writes exactly one UFS partition:
  partition: BOOTLOADER (sboot)
  image:     $IMAGE

The diagnostic preserves the complete engineering u-boot. Its signed entry
trampoline writes UBS1/OWN1 to PMU scratch, clears MINFORM, and resumes the
original entry. U-boot must then initialize its own USB and enter Samsung
Download mode. It does not issue an OTP command. The existing KEY2 programming
image remains at:
  $REPO/build/key2_program_chain/sboot.bin

First enter EUB when the engineering USB loader asks. Wait until the Samsung
Download/Odin screen reaches 100%. This script never starts Odin itself.
EOF
        echo
        echo "== sudo authentication (before the 6.5 second EUB window) =="
        authenticate_sudo

        set +e
        "$CUSTOM/run_custom_key_test.sh" efuse ecdsa_eng
        loader_rc=$?
        set -e
        case "$loader_rc" in
            0) ;;
            130|143) exit "$loader_rc" ;;
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

When the screen reaches 100%, run this exact command manually:

  sudo odin flash --BOOTLOADER $IMAGE

This script has not written the BOOTLOADER partition.
EOF
        ;;
    trigger)
        check_chain
        make -C "$REPO" build/epbl_boot_ufs_plain_probe.bin
        python3 "$REPO/tools/check_custom_key.py" \
            "$PAYLOAD" --candidate efuse
        cat <<EOF

BOOTLOADER image expected on UFS:
  $IMAGE

This trigger does not rewrite UFS. This is a retained legacy diagnostic: its
RAM payload still replaces the EPBL dispatch literal, installs a diagnostic
VBAR_EL3, and enters FWBL1 through fwbl1_noic_entry. It does not modify the
saved exception context. The inherited EUB USB handle is expected to close
after UFSLOAD!/UFSMETA!. Success is a fresh Samsung Download/Odin screen
reaching 100%, but a black screen cannot isolate the u-boot entry boundary.

The physical retention calibration returned PMU=NO and iRAM=NO, so a later
fresh-EUB trace cannot recover the entry markers. Restore the KEY2 programming
chain before the next programming attempt:
  $REPO/build/key2_program_chain/sboot.bin

== sudo authentication (before the 6.5 second EUB window) ==
EOF
        authenticate_sudo
        echo
        echo "Wait for 'Waiting for EUB 04e8:1234...' before entering EUB."
        echo
        set +e
        sudo "$HOUSTON/.venv/bin/python3" \
            "$REPO/tools/boot_nonsecure_probe.py" \
            --houston-dir "$HOUSTON" \
            --payload "$PAYLOAD" \
            --listen-ep1 20 \
            --output "$OUTPUT"
        probe_rc=$?
        set -e
        case "$probe_rc" in
            0) ;;
            130|143) exit "$probe_rc" ;;
            *)
                echo "EUB reader exited with status $probe_rc after handoff." >&2
                ;;
        esac
        cat <<EOF

The EUB handle closing is expected at this boundary.

Hardware PASS condition:
  the Samsung Download/Odin screen reappears and reaches 100%.

If that screen appears, BL2 entered the full custom-signed u-boot and u-boot
successfully initialized a new USB instance. Do not flash anything from that
screen unless the next test explicitly gives an image and its absolute path.
EOF
        ;;
    control-flash)
        check_control_chain
        command -v odin >/dev/null || {
            echo "error: odin/heimdall is not installed" >&2
            exit 1
        }
        cat <<EOF

This control writes exactly one UFS partition:
  partition: BOOTLOADER (sboot)
  image:     $CONTROL_IMAGE

This is the exact ecdsa_eng chain that already reached Samsung Download mode
when streamed over USB. Its u-boot has the original entry instruction, an
empty 0x17ce00 cave, and no OTP command injection. It isolates the UFS path
from the entry trampoline used by the preceding black-screen diagnostic.

First enter EUB when the engineering USB loader asks. Wait until the Samsung
Download/Odin screen reaches 100%. This script never starts Odin itself.
EOF
        echo
        echo "== sudo authentication (before the 6.5 second EUB window) =="
        authenticate_sudo

        set +e
        "$CUSTOM/run_custom_key_test.sh" efuse ecdsa_eng
        loader_rc=$?
        set -e
        case "$loader_rc" in
            0) ;;
            130|143) exit "$loader_rc" ;;
            *)
                echo "Engineering loader exited with status $loader_rc; continuing because Download-mode USB re-enumeration closes its EUB handle." >&2
                ;;
        esac

        cat <<EOF

Samsung Download mode should now be starting.

Do not run Odin until the Download/Odin screen reaches 100% and the device is
fully ready.

BOOTLOADER image:
  $CONTROL_IMAGE

When the screen reaches 100%, run this exact command manually:

  sudo odin flash --BOOTLOADER $CONTROL_IMAGE

This script has not written the BOOTLOADER partition.
EOF
        ;;
    control-trigger)
        check_control_chain
        make -C "$REPO" build/epbl_boot_ufs_plain_probe.bin
        python3 "$REPO/tools/check_custom_key.py" \
            "$PAYLOAD" --candidate efuse
        cat <<EOF

BOOTLOADER control image expected on UFS:
  $CONTROL_IMAGE

This trigger does not rewrite UFS. This is a retained legacy diagnostic: its
RAM payload still replaces the EPBL dispatch literal, installs a diagnostic
VBAR_EL3, and enters FWBL1 through fwbl1_noic_entry. The UFS image itself has
no u-boot entry trampoline and no OTP command injection.

Hardware PASS condition:
  a fresh Samsung Download/Odin screen appears and reaches 100%.

PASS proves that this shimmed UFS chain reaches the original ecdsa_eng u-boot.
Another black screen rules out only the u-boot entry trampoline as the cause;
it cannot separate the legacy FWBL1 shim from the stock downstream path.

== sudo authentication (before the 6.5 second EUB window) ==
EOF
        authenticate_sudo
        echo
        echo "Wait for 'Waiting for EUB 04e8:1234...' before entering EUB."
        echo
        set +e
        sudo "$HOUSTON/.venv/bin/python3" \
            "$REPO/tools/boot_nonsecure_probe.py" \
            --houston-dir "$HOUSTON" \
            --payload "$PAYLOAD" \
            --listen-ep1 20 \
            --output "/tmp/exynos9825_ubstage_control.bin"
        probe_rc=$?
        set -e
        case "$probe_rc" in
            0) ;;
            130|143) exit "$probe_rc" ;;
            *)
                echo "EUB reader exited with status $probe_rc after handoff." >&2
                ;;
        esac
        cat <<EOF

The inherited EUB handle may close at this boundary. Judge this control by the
new Samsung Download/Odin screen, not by a late EP1 record.

BOOTLOADER image used by this test:
  $CONTROL_IMAGE
EOF
        ;;
    silent-trigger)
        check_control_chain
        make -C "$REPO" build/epbl_boot_ufs_silent_probe.bin
        python3 "$REPO/tools/check_custom_key.py" \
            "$SILENT_PAYLOAD" --candidate efuse
        cat <<EOF

BOOTLOADER control image already expected on UFS:
  $CONTROL_IMAGE

This trigger does not rewrite UFS and does not require Odin. The RAM payload
loads the same uninstrumented ecdsa_eng chain, re-points the verification key,
and hands off without sending UFSLOAD!, UFSMETA!, or any other EP1 IN record.
It still inherits the legacy EPBL dispatch redirect, diagnostic VBAR_EL3, and
fwbl1_noic_entry shim. It changes no saved exception context and contains no
OTP command injection.

Hardware PASS condition:
  a fresh Samsung Download/Odin screen appears and reaches 100%.

PASS means the two early EP1 transfers disturbed the downstream UFS boot.
Another black screen rules those transfers out and leaves the UFS execution
state itself as the difference from the USB-streamed chain.

== sudo authentication (before the 6.5 second EUB window) ==
EOF
        authenticate_sudo
        echo
        echo "Wait for 'Waiting for EUB 04e8:1234...' before entering EUB."
        echo
        set +e
        sudo "$HOUSTON/.venv/bin/python3" \
            "$REPO/tools/boot_nonsecure_probe.py" \
            --houston-dir "$HOUSTON" \
            --payload "$SILENT_PAYLOAD" \
            --listen-ep1 20 \
            --allow-no-records \
            --output "/tmp/exynos9825_ubstage_silent.bin"
        probe_rc=$?
        set -e
        case "$probe_rc" in
            0) ;;
            130|143) exit "$probe_rc" ;;
            *)
                echo "EUB reader exited with status $probe_rc after the silent handoff." >&2
                ;;
        esac
        cat <<EOF

No probe record is expected from this payload. The inherited EUB handle should
close when the stock chain takes ownership. Judge the result only by whether a
new Samsung Download/Odin screen appears and reaches 100%.

BOOTLOADER image used by this test:
  $CONTROL_IMAGE
EOF
        ;;
    force-download-flash)
        check_forced_download_chain
        command -v odin >/dev/null || {
            echo "error: odin/heimdall is not installed" >&2
            exit 1
        }
        cat <<EOF

This diagnostic writes exactly one UFS partition:
  partition: BOOTLOADER (sboot)
  image:     $FORCED_IMAGE

Its u-boot body matches the proven ecdsa_eng image except for two verified
instructions: the stale pre-fork MAGIC_CODE read returns zero, and
s5p_check_download returns the legitimate Download reason 4. There is no entry
trampoline and no OTP command injection.

First enter EUB when the engineering USB loader asks. Wait until the Samsung
Download/Odin screen reaches 100%. This script never starts Odin itself.

== sudo authentication (before the 6.5 second EUB window) ==
EOF
        authenticate_sudo

        set +e
        "$CUSTOM/run_custom_key_test.sh" efuse ecdsa_eng
        loader_rc=$?
        set -e
        case "$loader_rc" in
            0) ;;
            130|143) exit "$loader_rc" ;;
            *)
                echo "Engineering loader exited with status $loader_rc; continuing because Download-mode USB re-enumeration closes its EUB handle." >&2
                ;;
        esac

        cat <<EOF

Samsung Download mode should now be starting.

Do not run Odin until the Download/Odin screen reaches 100% and the device is
fully ready.

BOOTLOADER image:
  $FORCED_IMAGE

When the screen reaches 100%, run this exact command manually:

  sudo odin flash --BOOTLOADER $FORCED_IMAGE

This script has not written the BOOTLOADER partition.
EOF
        ;;
    force-download-trigger)
        check_forced_download_chain
        make -C "$REPO" build/epbl_boot_ufs_silent_probe.bin
        python3 "$REPO/tools/check_custom_key.py" \
            "$SILENT_PAYLOAD" --candidate efuse
        cat <<EOF

BOOTLOADER image expected on UFS:
  $FORCED_IMAGE

This trigger does not rewrite UFS and does not require Odin. The RAM payload
uses the legacy silent handoff: it sends no success-path EP1 record and makes
no saved-context change, but still installs the EPBL dispatch redirect,
diagnostic VBAR_EL3, and fwbl1_noic_entry shim. If BL2 reaches u-boot's main
flow, the flashed image forces Download reason 4 and must take the real Samsung
Download path.

Hardware PASS condition:
  a fresh Samsung Download/Odin screen appears and reaches 100%.

PASS proves the shimmed FWBL1 and BL2 path reached the custom-signed u-boot.
Another black screen remains ambiguous because this action still uses the
legacy FWBL1 shim; it does not justify another KEY2 attempt.

== sudo authentication (before the 6.5 second EUB window) ==
EOF
        authenticate_sudo
        echo
        echo "Wait for 'Waiting for EUB 04e8:1234...' before entering EUB."
        echo
        set +e
        sudo "$HOUSTON/.venv/bin/python3" \
            "$REPO/tools/boot_nonsecure_probe.py" \
            --houston-dir "$HOUSTON" \
            --payload "$SILENT_PAYLOAD" \
            --listen-ep1 20 \
            --allow-no-records \
            --output "/tmp/exynos9825_ubstage_forced_download.bin"
        probe_rc=$?
        set -e
        case "$probe_rc" in
            0) ;;
            130|143) exit "$probe_rc" ;;
            *)
                echo "EUB reader exited with status $probe_rc after the silent handoff." >&2
                ;;
        esac
        cat <<EOF

No probe record is expected. Judge the result only by whether a new Samsung
Download/Odin screen appears and reaches 100%.

BOOTLOADER image used by this test:
  $FORCED_IMAGE
EOF
        ;;
    native-trigger)
        check_forced_download_chain
        check_native_payload
        cat <<EOF

BOOTLOADER image expected on UFS:
  $FORCED_IMAGE

This trigger does not rewrite UFS and does not require Odin. The preceding
black-screen controls shared a hidden diagnostic path: despite their names,
both still replaced the EPBL dispatch literal and entered FWBL1 through
fwbl1_noic_entry.

This payload keeps only the first-line relocation stager needed because EPBL
overwrites 0x02022000. After the verified UFS load it:
  - sends no success-path EP1 record;
  - installs no diagnostic VBAR;
  - leaves the EPBL dispatch literal at 0x02020128;
  - makes no FWBL1 or saved-context patch;
  - enters the BootROM helper at 0x0001c9a0 with LR=0x00000250.

The I-cache is disabled immediately before the EPBL entry so the overwritten
first cache line is fetched from iRAM. The authentic FWBL1 prologue enables it
again itself.

Hardware PASS condition:
  a fresh Samsung Download/Odin screen appears and reaches 100%.

PASS proves the previous FWBL1 shim caused the black screen. Another black
screen means the remaining difference is earlier than that shim or within the
stock UFS boot state; it still does not justify another KEY2 programming run.

== sudo authentication (before the 6.5 second EUB window) ==
EOF
        authenticate_sudo
        echo
        echo "Wait for 'Waiting for EUB 04e8:1234...' before entering EUB."
        echo
        set +e
        sudo "$HOUSTON/.venv/bin/python3" \
            "$REPO/tools/boot_nonsecure_probe.py" \
            --houston-dir "$HOUSTON" \
            --payload "$NATIVE_PAYLOAD" \
            --listen-ep1 20 \
            --allow-no-records \
            --output "/tmp/exynos9825_ubstage_native.bin"
        probe_rc=$?
        set -e
        case "$probe_rc" in
            0) ;;
            130|143) exit "$probe_rc" ;;
            *)
                echo "EUB reader exited with status $probe_rc after the native handoff." >&2
                ;;
        esac
        cat <<EOF

No probe record is expected on a successful handoff. Judge the result only by
whether a new Samsung Download/Odin screen appears and reaches 100%.

BOOTLOADER image used by this test:
  $FORCED_IMAGE

This command did not write the BOOTLOADER partition.
EOF
        ;;
    native-diagnose)
        check_forced_download_chain
        check_native_diagnostic_payload
        cat <<EOF

BOOTLOADER image already expected on UFS:
  $FORCED_IMAGE

Hardware returned EUNPOST! with selector=1, verifier=1 and
PTR_SECUREBOOT_KEY=0x020254a8. A subsequent native-diagnose run under the
confirmed PR #12 same-handle policy still returned no EUNPRE!! or EUNRET!!.
Hardware subsequently returned EUNTIME!, proving that 0x18768 completed while
EP1 remained usable. This action remains the final combined pre-entry snapshot
and return sentinel; use native-flag-diagnose first to isolate the following
0x16a10 boundary.

This is a RAM-only diagnostic. It does not rewrite UFS and does not require
Odin. It uses the same native handoff as native-trigger and adds exactly one
completed record immediately before I-cache is disabled and the authentic
EPBL is entered:

  EUNPRE!!  boot state, key-selector result, post-load result,
            0x15860990, PTR_IS_SECUREBOOT, 0x02020128, SCTLR_EL3 and SP

For this diagnostic only, LR points to a relocated failure sentinel. A
successful EPBL/FWBL1/BL2 path never returns there. If EPBL does return, the
sentinel emits:

  EUNRET!!  EPBL return value and the relevant iRAM state after the return

This avoids executing BootROM's 0x250 epilogue on the Houston callback stack,
which would hide an EPBL failure behind a silent black screen.

Interpretation:
  - EUNPRE!! followed by USB disconnect, without EUNRET!!: the host-side
    ENODEV is only the old BootROM USB instance leaving; EPBL did not return
    while that channel remained usable.
  - EUNRET!!: the authentic EPBL returned and the record localizes the failure.
  - no EUNPRE!!: the stop happened before the final native snapshot, or EP1
    could not complete that transfer.

== sudo authentication (before the 6.5 second EUB window) ==
EOF
        authenticate_sudo
        rm -f /tmp/exynos9825_ubstage_native_diag.bin
        echo
        echo "Wait for 'Waiting for EUB 04e8:1234...' before entering EUB."
        echo
        set +e
        sudo "$HOUSTON/.venv/bin/python3" \
            "$REPO/tools/boot_nonsecure_probe.py" \
            --houston-dir "$HOUSTON" \
            --payload "$NATIVE_DIAG_PAYLOAD" \
            --listen-ep1 20 \
            --output "/tmp/exynos9825_ubstage_native_diag.bin"
        probe_rc=$?
        set -e
        case "$probe_rc" in
            0) ;;
            130|143) exit "$probe_rc" ;;
            *)
                echo "Native diagnostic exited with status $probe_rc; inspect the decoded EUNPRE/EUNRET record above." >&2
                ;;
        esac
        cat <<EOF

BOOTLOADER image used by this RAM-only diagnostic:
  $FORCED_IMAGE

This command did not write the BOOTLOADER partition.
EOF
        ;;
    native-load-diagnose)
        check_forced_download_chain
        check_native_load_diagnostic_payload
        cat <<EOF

BOOTLOADER image already expected on UFS:
  $FORCED_IMAGE

This is a RAM-only diagnostic. It does not rewrite UFS and does not require
Odin. The local Houston checkout contains PR #12, and boot_nonsecure_probe.py
retains the same claimed EUB handle after overwrite_iram(); the hardware log
prints that policy before ACE is triggered.

The payload uses the unhooked native EPBL/FWBL1 handoff and adds only the two
existing completed records immediately after BootROM 0xcc68 returns success:

  UFSLOAD!  loader return, boot state and loaded EPBL header
  UFSMETA!  iRAM metadata left by the storage loader

It installs no diagnostic VBAR, no FWBL1 shim, no dispatch redirect and no
saved-context modification. After both records complete, it continues through
the native handoff with LR=0x250.

Interpretation:
  - UFSLOAD! and UFSMETA!: PR #12 handle retention and the UFS load both work;
    the black-screen cause is later than 0xcc68.
  - no record before ENODEV: 0xcc68 did not return success while EP1 remained
    usable, which localizes the loss before the selector/post-load preparation.
  - a decoded failure record: use its status instead of treating ENODEV as the
    cause.

== sudo authentication (before the 6.5 second EUB window) ==
EOF
        authenticate_sudo
        rm -f /tmp/exynos9825_ubstage_native_load_diag.bin
        echo
        echo "Wait for 'Waiting for EUB 04e8:1234...' before entering EUB."
        echo
        set +e
        sudo "$HOUSTON/.venv/bin/python3" \
            "$REPO/tools/boot_nonsecure_probe.py" \
            --houston-dir "$HOUSTON" \
            --payload "$NATIVE_LOAD_DIAG_PAYLOAD" \
            --listen-ep1 20 \
            --output "/tmp/exynos9825_ubstage_native_load_diag.bin"
        probe_rc=$?
        set -e
        case "$probe_rc" in
            0) ;;
            130|143) exit "$probe_rc" ;;
            *)
                echo "Native post-load diagnostic exited with status $probe_rc; inspect UFSLOAD/UFSMETA or a decoded failure above." >&2
                ;;
        esac
        cat <<EOF

BOOTLOADER image used by this RAM-only diagnostic:
  $FORCED_IMAGE

This command did not write the BOOTLOADER partition.
EOF
        ;;
    native-postload-diagnose)
        check_forced_download_chain
        check_native_postload_diagnostic_payload
        cat <<EOF

BOOTLOADER image already expected on UFS:
  $FORCED_IMAGE

This is a RAM-only diagnostic. It does not rewrite UFS and does not require
Odin. The preceding hardware run proved that the PR #12 handle remained live
and that BootROM 0xcc68 loaded the UFS EPBL successfully.

This revision remains silent during the UFS load and key-selector call. It
emits exactly one completed record immediately after BootROM 0x5b58 returns
and before the final 0x18768 timing copy and 0x16a10 boot-flag call:

  EUNPOST!  selector result, verifier result, active key pointer,
            post-load state/timing, SEC0, boot state and CurrentEL

It installs no diagnostic VBAR, no FWBL1 shim, no dispatch redirect and no
saved-context modification. It keeps the native LR=0x250 handoff.

Interpretation:
  - EUNPOST! with verifier return 1: selector and custom-key BL1 verification
    succeeded; the missing EUNPRE boundary is in the two final preparation
    calls or their effect on EP1.
  - no EUNPOST! before ENODEV: execution or EP1 availability was lost inside
    the selector/0x5b58 interval.
  - EUNPFAIL: 0x5b58 returned failure; use the decoded fields to diagnose it.

== sudo authentication (before the 6.5 second EUB window) ==
EOF
        authenticate_sudo
        rm -f /tmp/exynos9825_ubstage_native_postload_diag.bin
        echo
        echo "Wait for 'Waiting for EUB 04e8:1234...' before entering EUB."
        echo
        set +e
        sudo "$HOUSTON/.venv/bin/python3" \
            "$REPO/tools/boot_nonsecure_probe.py" \
            --houston-dir "$HOUSTON" \
            --payload "$NATIVE_POSTLOAD_DIAG_PAYLOAD" \
            --listen-ep1 20 \
            --output "/tmp/exynos9825_ubstage_native_postload_diag.bin"
        probe_rc=$?
        set -e
        case "$probe_rc" in
            0) ;;
            130|143) exit "$probe_rc" ;;
            *)
                echo "Native postload diagnostic exited with status $probe_rc; inspect EUNPOST/EUNPFAIL above." >&2
                ;;
        esac
        cat <<EOF

BOOTLOADER image used by this RAM-only diagnostic:
  $FORCED_IMAGE

This command did not write the BOOTLOADER partition.
EOF
        ;;
    native-timing-diagnose)
        check_forced_download_chain
        check_native_timing_diagnostic_payload
        cat <<EOF

BOOTLOADER image already expected on UFS:
  $FORCED_IMAGE

This is a RAM-only diagnostic. It does not rewrite UFS and does not require
Odin. Hardware already returned EUNPOST! with selector=1, verifier=1 and the
custom key at 0x020254a8, but the later EUNPRE!! snapshot did not arrive.

This revision stays silent through UFS loading and BL1 verification. It emits
one completed record immediately after BootROM 0x18768 returns and before
0x16a10 sets boot flag 0x00800000:

  EUNTIME!  selector and verifier returns, entry timing delta, boot flags
             before the update, custom key pointer, authentic EPBL entry
             words, SCTLR_EL3 and CurrentEL

It installs no diagnostic VBAR, no FWBL1 shim, no dispatch redirect and no
saved-context modification. It keeps the native LR=0x250 handoff.

Interpretation:
  - EUNTIME!: 0x18768 returned; the missing EUNPRE boundary is after the
    timing helper, starting with 0x16a10 or its effect on EP1.
  - no EUNTIME! after the proven EUNPOST!: execution or EP1 availability was
    lost inside 0x18768.
  - EUNPFAIL: the earlier 0x5b58 verifier unexpectedly failed.

== sudo authentication (before the 6.5 second EUB window) ==
EOF
        authenticate_sudo
        rm -f /tmp/exynos9825_ubstage_native_timing_diag.bin
        echo
        echo "Wait for 'Waiting for EUB 04e8:1234...' before entering EUB."
        echo
        set +e
        sudo "$HOUSTON/.venv/bin/python3" \
            "$REPO/tools/boot_nonsecure_probe.py" \
            --houston-dir "$HOUSTON" \
            --payload "$NATIVE_TIMING_DIAG_PAYLOAD" \
            --listen-ep1 20 \
            --output "/tmp/exynos9825_ubstage_native_timing_diag.bin"
        probe_rc=$?
        set -e
        case "$probe_rc" in
            0) ;;
            130|143) exit "$probe_rc" ;;
            *)
                echo "Native timing diagnostic exited with status $probe_rc; inspect EUNTIME/EUNPFAIL above." >&2
                ;;
        esac
        cat <<EOF

BOOTLOADER image used by this RAM-only diagnostic:
  $FORCED_IMAGE

This command did not write the BOOTLOADER partition.
EOF
        ;;
    native-flag-diagnose)
        check_forced_download_chain
        check_native_flag_diagnostic_payload
        cat <<EOF

BOOTLOADER image already expected on UFS:
  $FORCED_IMAGE

This is a RAM-only diagnostic. It does not rewrite UFS and does not require
Odin. Hardware returned EUNTIME! with selector=1, verifier=1, timing delta
0x000003ce, boot flags 0x00300edf, the custom key at 0x020254a8 and both
authentic EPBL entry instructions intact. Therefore 0x18768 returned while
EP1 was still usable.

This revision stays silent through UFS loading, BL1 verification and the
entry-timing helper. It emits one completed record immediately after BootROM
0x16a10 returns and before the native entry validation:

  EUNFLAG!  selector and verifier returns, entry timing delta, boot flags
             after the update, custom key pointer, dispatch literal, packed
             EPBL entry/hook instructions, SCTLR_EL3 and CurrentEL

The expected flag transition is 0x00300edf -> 0x00b00edf: bit 0x00800000 must
be set. The payload installs no diagnostic VBAR, no FWBL1 shim, no dispatch
redirect and no saved-context modification. It keeps native LR=0x250.

Interpretation:
  - EUNFLAG! with the final bit present: 0x16a10 returned and every input used
    by the subsequent native validation remained intact.
  - no EUNFLAG! after the proven EUNTIME!: execution or EP1 availability was
    lost inside 0x16a10 or as its immediate side effect.
  - EUNPFAIL: the earlier 0x5b58 verifier unexpectedly failed.

== sudo authentication (before the 6.5 second EUB window) ==
EOF
        authenticate_sudo
        rm -f /tmp/exynos9825_ubstage_native_flag_diag.bin
        echo
        echo "Wait for 'Waiting for EUB 04e8:1234...' before entering EUB."
        echo
        set +e
        sudo "$HOUSTON/.venv/bin/python3" \
            "$REPO/tools/boot_nonsecure_probe.py" \
            --houston-dir "$HOUSTON" \
            --payload "$NATIVE_FLAG_DIAG_PAYLOAD" \
            --listen-ep1 20 \
            --output "/tmp/exynos9825_ubstage_native_flag_diag.bin"
        probe_rc=$?
        set -e
        case "$probe_rc" in
            0) ;;
            130|143) exit "$probe_rc" ;;
            *)
                echo "Native boot-flag diagnostic exited with status $probe_rc; inspect EUNFLAG/EUNPFAIL above." >&2
                ;;
        esac
        cat <<EOF

BOOTLOADER image used by this RAM-only diagnostic:
  $FORCED_IMAGE

This command did not write the BOOTLOADER partition.
EOF
        ;;
    native-cold-diagnose)
        check_forced_download_chain
        check_native_cold_diagnostic_payload
        cat <<EOF

BOOTLOADER image already expected on UFS:
  $FORCED_IMAGE

This is a RAM-only diagnostic and boot attempt. It does not rewrite UFS, does
not require Odin and does not issue an OTP command. Hardware returned
EUNFLAG! with selector=1, verifier=1, boot flags 0x00b00edf, the authentic
EPBL entry/hook instructions and dispatch literal intact. The complete stock
pre-entry sequence is therefore proven.

The authentic EPBL immediately reads 0x15860990. Value 1 selects its warm
branch and uses the 32-bit state at 0x02020128 plus 0x10 as the target. An
earlier hardware capture observed gate value 1 with residual dispatch state.

This revision runs after all native validation. It reads the current gate and
state, checks the authenticated branch instruction at 0x02022028, replaces
only that instruction in the verified RAM copy with an unconditional branch
to the EPBL's own cold loader, and emits:

  EUNCOLD!  original gate and dispatch state, final flags, original and
             patched branch instructions, dispatch literal and CurrentEL

It then disables I-cache and enters the original BootROM helper at 0x1c9a0
with LR=0x250. The EPBL, FWBL1, saved context and persistent BOOTLOADER image
otherwise remain unchanged.

Interpretation:
  - EUNCOLD! plus a new Samsung Download/Odin screen reaching 100%: the stale
    warm path was the blocker and the UFS cold chain reached u-boot.
  - EUNCOLD! followed by a black screen: the original gate/state are proven
    and the stop is downstream of the forced cold dispatch.
  - no EUNCOLD! after the proven EUNFLAG!: the gate read or branch-patch
    boundary did not complete while EP1 remained usable.

== sudo authentication (before the 6.5 second EUB window) ==
EOF
        authenticate_sudo
        rm -f /tmp/exynos9825_ubstage_native_cold_diag.bin
        echo
        echo "Wait for 'Waiting for EUB 04e8:1234...' before entering EUB."
        echo
        set +e
        sudo "$HOUSTON/.venv/bin/python3" \
            "$REPO/tools/boot_nonsecure_probe.py" \
            --houston-dir "$HOUSTON" \
            --payload "$NATIVE_COLD_DIAG_PAYLOAD" \
            --listen-ep1 20 \
            --output "/tmp/exynos9825_ubstage_native_cold_diag.bin"
        probe_rc=$?
        set -e
        case "$probe_rc" in
            0) ;;
            130|143) exit "$probe_rc" ;;
            *)
                echo "Native cold-path diagnostic exited with status $probe_rc; inspect EUNCOLD/EUNPFAIL above." >&2
                ;;
        esac
        cat <<EOF

BOOTLOADER image used by this RAM-only diagnostic:
  $FORCED_IMAGE

This command did not write the BOOTLOADER partition.
EOF
        ;;
    native-force-cold)
        check_forced_download_chain
        check_native_force_cold_payload
        cat <<EOF

BOOTLOADER image already expected on UFS:
  $FORCED_IMAGE

This is a RAM-only diagnostic and boot attempt. It does not rewrite UFS, does
not require Odin and does not issue an OTP command.

Hardware completed EUNFLAG!, but both EUNPRE!! and EUNCOLD! disappeared before
their first record. The first operation unique to both missing records was a
read from 0x15860990. This revision deliberately does not read that register or
the residual dispatch state at 0x02020128.

After the already-proven native preparation and validation it checks the exact
gate-load word 0x580002d4 at 0x02022018, replaces only that RAM instruction
with a direct branch 0x14000006 to the original cold loader at 0x02022030, and
emits:

  EUNFORC!  final flags, original gate-load and patched direct-branch words,
             authentic dispatch literal and entry instruction, SCTLR_EL3 and
             CurrentEL

It then disables I-cache and enters BootROM helper 0x1c9a0 with LR=0x250. The
patched instruction enters the EPBL's original cold loader without evaluating
the suspect warm-state MMIO value.

Interpretation:
  - EUNFORC! plus a new Samsung Download/Odin screen reaching 100%: the EPBL
    warm-state gate sequence was the blocker and the forced cold chain booted.
  - EUNFORC! followed by a black screen: the RAM override completed and the
    stop is downstream of the cold branch.
  - no EUNFORC!: the instruction read/write or EP1 boundary failed before handoff;
    the test still performed no persistent write.

== sudo authentication (before the 6.5 second EUB window) ==
EOF
        authenticate_sudo
        rm -f /tmp/exynos9825_ubstage_native_force_cold.bin
        echo
        echo "Wait for 'Waiting for EUB 04e8:1234...' before entering EUB."
        echo
        set +e
        sudo "$HOUSTON/.venv/bin/python3" \
            "$REPO/tools/boot_nonsecure_probe.py" \
            --houston-dir "$HOUSTON" \
            --payload "$NATIVE_FORCE_COLD_PAYLOAD" \
            --listen-ep1 20 \
            --output "/tmp/exynos9825_ubstage_native_force_cold.bin"
        probe_rc=$?
        set -e
        case "$probe_rc" in
            0) ;;
            130|143) exit "$probe_rc" ;;
            *)
                echo "Native force-cold attempt exited with status $probe_rc; inspect EUNFORC/EUNPFAIL above." >&2
                ;;
        esac
        cat <<EOF

BOOTLOADER image used by this RAM-only diagnostic:
  $FORCED_IMAGE

This command did not write the BOOTLOADER partition.
EOF
        ;;
    native-triple-stock)
        check_native_triple_stock_payload
        cat <<EOF

BOOTLOADER partition: this action expects the STOCK Samsung sboot, which is
what the board holds after restore_stock_sboot.sh or an Odin BL flash. It
writes nothing, requires no Odin step and issues no OTP command.

Why this build exists. Every record emitted at or before the 0x16a10
boot-flag boundary arrived (EUNTIME!, EUNFLAG!). Every record emitted after
the native entry validation was lost (EUNPRE!!, EUNCOLD!, EUNFORC!) whether it
read 0x15860990, wrote an EPBL instruction, or did neither. Each of those
bisects moved the operation and the position at the same time, so neither was
ever tested alone.

This payload emits the SAME read-only record four times:

  EUN3REC0  at the proven EUNTIME! position, WITHOUT the two suspect reads
  EUN3REC1  at the proven EUNTIME! position, with them
  EUN3REC2  at the proven EUNFLAG! position, after 0x16a10
  EUN3REC3  at the lost position, after the native entry validation

EUN3REC0 is the baseline. Without it, a run where the reads themselves close
the channel would return nothing at all and be indistinguishable from a run
that failed upstream. Nothing is written in any of them: the loaded EPBL stays
byte-for-byte authentic and is entered through the stock BootROM helper at
0x1c9a0 with LR=0x250.

PTR_SECUREBOOT_KEY is left alone, so BootROM verifies Samsung own image
against Samsung own key: this is a fully stock trust path.

What the SCREEN shows is the stronger signal, and it is reported separately
from the records. Stock u-boot has none of the patches the resigned chain
needed against stale EUB state, and it still runs s5p_check_download, so a
successful handoff may land in Download mode, the USB RECOVERY prompt, a
Samsung logo or Android. ANY visible screen proves the instrumented native
handoff reached u-boot, which would move the whole problem into the resigned
chain. A black screen means the handoff fails even with Samsung own image and
Samsung own key.

Interpretation of the records:
  - none: upstream of everything measured, or an unreliable channel. The
    EUNTIME! position worked before, so repeat once before concluding.
  - 0 only: reading 0x15860990 / 0x02020128 is itself what closes the channel.
  - 0 and 1: the reads are harmless; something from the boot-flag call onward
    kills every later send. EUN3REC1 still hands us the warm/cold gate value.
  - 0, 1, 2: the boundary is purely positional, after the entry validation.
  - all four: no operation is responsible and the earlier losses were
    nondeterministic.

== sudo authentication (before the 6.5 second EUB window) ==
EOF
        authenticate_sudo
        rm -f /tmp/exynos9825_ubstage_native_triple_stock.bin
        echo
        echo "Wait for 'Waiting for EUB 04e8:1234...' before entering EUB."
        echo
        set +e
        sudo "$HOUSTON/.venv/bin/python3" \
            "$REPO/tools/boot_nonsecure_probe.py" \
            --houston-dir "$HOUSTON" \
            --payload "$NATIVE_TRIPLE_STOCK_PAYLOAD" \
            --listen-ep1 25 \
            --output "/tmp/exynos9825_ubstage_native_triple_stock.bin"
        probe_rc=$?
        set -e
        case "$probe_rc" in
            0) ;;
            130|143) exit "$probe_rc" ;;
            *)
                echo "Native triple-record run exited with status $probe_rc; count how many of EUN3REC1/2/3 appear above." >&2
                ;;
        esac
        cat <<EOF

This command did not write the BOOTLOADER partition and did not issue an OTP
command. Report which EUN3REC* records arrived AND exactly what the screen
did: black, Samsung logo, Download/Odin, USB RECOVERY prompt, or Android.
A plain power-on afterwards boots the stock chain normally either way.
EOF
        ;;
    native-stockkey)
        # Requires the STOCK sboot on BOOTLOADER. The redirect machinery runs
        # in full, aimed at Samsung's own fused KEY value, so verification
        # passes for the same reason it does on a stock boot. Against the one
        # row that boots, the only remaining difference is where
        # PTR_SECUREBOOT_KEY points.
        make -C "$REPO" build/epbl_boot_ufs_native_stockkey_probe.bin
        python3 - "$STOCK_SBOOT" "$STOCK_EPBL" <<'PY'
import sys, pathlib
src, dst = sys.argv[1], sys.argv[2]
pathlib.Path(dst).parent.mkdir(parents=True, exist_ok=True)
pathlib.Path(dst).write_bytes(pathlib.Path(src).read_bytes()[:0x3000])
PY
        python3 "$REPO/tools/check_native_ufs_payload.py" --triple-records \
            "$STOCKKEY_ELF" "$STOCKKEY_PAYLOAD" "$STOCK_EPBL"
        cat <<EOF

BOOTLOADER image expected on UFS:
  $STOCK_SBOOT     <-- STOCK, not a resigned chain

RAM-only: no Odin step and no OTP command. The screen is the oracle. A boot
clears the redirect and puts the failure in our ST1 identity; a black screen
says the redirect itself breaks the UFS path.

== sudo authentication (before the 6.5 second EUB window) ==
EOF
        authenticate_sudo
        rm -f /tmp/exynos9825_ubstage_native_stockkey.bin
        echo
        echo "Wait for 'Waiting for EUB 04e8:1234...' before entering EUB."
        echo
        set +e
        sudo "$HOUSTON/.venv/bin/python3" \
            "$REPO/tools/boot_nonsecure_probe.py" \
            --houston-dir "$HOUSTON" \
            --payload "$STOCKKEY_PAYLOAD" \
            --listen-ep1 25 \
            --output "/tmp/exynos9825_ubstage_native_stockkey.bin"
        probe_rc=$?
        set -e
        case "$probe_rc" in
            0|130|143) ;;
            *) echo "native-stockkey exited with status $probe_rc; the screen is what matters." >&2 ;;
        esac
        echo
        echo "Report what the SCREEN did. Records carry no information here."
        ;;

    native-keysafe)
        # native-triple with one variable changed: the 32 key bytes the BootROM
        # verifier dereferences are copied to PROBE_CUSTOM_KEY_LOW (0x02021800)
        # and the pointer aims there, instead of at custom_boot_key inside the
        # relocated worker at 0x02025000. Needs the same resigned image on UFS.
        case "${2:-minimal}" in
            minimal) KS_IMAGE="$CUSTOM/minimal/sboot.bin"; KS_EPBL="$CUSTOM/minimal/sboot/epbl.bin" ;;
            eng)     KS_IMAGE="$CONTROL_IMAGE";            KS_EPBL="$CUSTOM/ecdsa_eng/sboot/epbl.bin" ;;
            *)       echo "usage: $0 native-keysafe {minimal|eng}" >&2; exit 2 ;;
        esac
        [[ -f "$KS_IMAGE" && -f "$KS_EPBL" ]] || {
            echo "error: missing $KS_IMAGE or $KS_EPBL" >&2; exit 1; }
        make -C "$REPO" build/epbl_boot_ufs_native_keysafe_probe.bin
        python3 "$REPO/tools/check_native_ufs_payload.py" --triple-records \
            "$KEYSAFE_ELF" "$KEYSAFE_PAYLOAD" "$KS_EPBL"
        python3 "$REPO/tools/check_custom_key.py" "$KEYSAFE_PAYLOAD" --candidate efuse
        cat <<EOF

BOOTLOADER image expected on UFS:
  $KS_IMAGE

RAM-only: no Odin step and no OTP command. The screen is the oracle --
a boot means the key was being clobbered where it used to live, a black
screen means it was not.

== sudo authentication (before the 6.5 second EUB window) ==
EOF
        authenticate_sudo
        rm -f /tmp/exynos9825_ubstage_native_keysafe.bin
        echo
        echo "Wait for 'Waiting for EUB 04e8:1234...' before entering EUB."
        echo
        set +e
        sudo "$HOUSTON/.venv/bin/python3" \
            "$REPO/tools/boot_nonsecure_probe.py" \
            --houston-dir "$HOUSTON" \
            --payload "$KEYSAFE_PAYLOAD" \
            --listen-ep1 25 \
            --output "/tmp/exynos9825_ubstage_native_keysafe.bin"
        probe_rc=$?
        set -e
        case "$probe_rc" in
            0|130|143) ;;
            *) echo "native-keysafe exited with status $probe_rc; the screen is what matters." >&2 ;;
        esac
        echo
        echo "Report what the SCREEN did. Records carry no information here."
        ;;

    native-triple)
        # Which resigned image is on UFS. "eng" is the default because it is
        # the exact image already proven over USB, so a black screen with it
        # cannot be blamed on the forced-download patches.
        case "${2:-eng}" in
            eng)    TRIPLE_IMAGE="$CONTROL_IMAGE"; TRIPLE_EPBL="$CUSTOM/ecdsa_eng/sboot/epbl.bin" ;;
            forced) TRIPLE_IMAGE="$FORCED_IMAGE";  TRIPLE_EPBL="$FORCED_CHAIN/sboot/epbl.bin" ;;
            # Stock stages under Samsung's own ST2-TEE key, with only the ST1
            # anchor ours. It splits the black screen: if this boots, the UFS
            # failure is our resigned stages; if it is black too, it is the
            # EPBL surgery, even though the BootROM verifier returns 1.
            minimal) TRIPLE_IMAGE="$CUSTOM/minimal/sboot.bin"; TRIPLE_EPBL="$CUSTOM/minimal/sboot/epbl.bin" ;;
            # Same, but Samsung's st2_key_ree kept and the container footer
            # left stale. 226 bytes from stock, all of them the ST1 anchor.
            keepree) TRIPLE_IMAGE="$CUSTOM/minimal_keepree/sboot.bin"; TRIPLE_EPBL="$CUSTOM/minimal_keepree/sboot/epbl.bin" ;;
            *)      echo "usage: $0 native-triple {eng|forced|minimal|keepree}" >&2; exit 2 ;;
        esac
        [[ -f "$TRIPLE_IMAGE" && -f "$TRIPLE_EPBL" ]] || {
            echo "error: missing $TRIPLE_IMAGE or $TRIPLE_EPBL" >&2
            exit 1
        }
        check_native_triple_payload "$TRIPLE_EPBL"
        cat <<EOF

BOOTLOADER image expected on UFS:
  $TRIPLE_IMAGE

Same four-record read-only measurement as native-triple-stock, but with
PTR_SECUREBOOT_KEY redirected at the custom key, for a board that holds the
resigned chain. RAM-only: no Odin step and no OTP command.

Do NOT run this on a board holding the stock sboot: the BootROM would verify
Samsung image against our key and reject it. Use native-triple-stock there.

The payload only mirrors EPBL bytes 0x40-0xC0, which are identical in the
stock, ecdsa_eng and forced-download EPBLs, so the same payload is valid for
either resigned image.

== sudo authentication (before the 6.5 second EUB window) ==
EOF
        authenticate_sudo
        rm -f /tmp/exynos9825_ubstage_native_triple.bin
        echo
        echo "Wait for 'Waiting for EUB 04e8:1234...' before entering EUB."
        echo
        set +e
        sudo "$HOUSTON/.venv/bin/python3" \
            "$REPO/tools/boot_nonsecure_probe.py" \
            --houston-dir "$HOUSTON" \
            --payload "$NATIVE_TRIPLE_PAYLOAD" \
            --listen-ep1 25 \
            --output "/tmp/exynos9825_ubstage_native_triple.bin"
        probe_rc=$?
        set -e
        case "$probe_rc" in
            0) ;;
            130|143) exit "$probe_rc" ;;
            *)
                echo "Native triple-record run exited with status $probe_rc; count how many of EUN3REC1/2/3 appear above." >&2
                ;;
        esac
        cat <<EOF

BOOTLOADER image used by this RAM-only diagnostic:
  $TRIPLE_IMAGE

This command did not write the BOOTLOADER partition. Report which EUN3REC*
records arrived AND what the screen did.
EOF
        ;;
    native-triple-restore)
        check_native_triple_restore_payload
        cat <<EOF

BOOTLOADER image expected on UFS:
  $CONTROL_IMAGE

RAM-only: no Odin step, no partition write, no OTP command.

One variable against the native-triple run that went black. Identical in
every other respect, including the four records. The payload saves whatever
pointer the BootROM key selector left in 0x0202006c, redirects it at our key
for the 0x5b58 verification exactly as before, and then writes the original
value back as soon as that verifier returns.

Neither the EPBL nor the decrypted FWBL1 contains any reference to
0x0202006c, so a correct chain must not notice this. The reason to test it is
that our key lives at 0x020254a8, in the 0x1000-byte gap between the loaded
EPBL and FWBL1 -- exactly where a storage driver would place descriptors or
bounce buffers. The USB-proven run never ran that driver, and the successful
stock run never redirected the pointer, so this combination has never been
isolated.

Interpretation:
  - any visible screen: some ROM code reached from the EPBL does read
    0x0202006c after the handoff, and our key in that gap is being destroyed
    by the UFS path. The fix is to relocate the key, not to change the chain.
  - black again: the pointer is genuinely irrelevant downstream, and the
    difference is the resigned image bytes on the storage path alone.

== sudo authentication (before the 6.5 second EUB window) ==
EOF
        authenticate_sudo
        rm -f /tmp/exynos9825_ubstage_native_triple_restore.bin
        echo
        echo "Wait for 'Waiting for EUB 04e8:1234...' before entering EUB."
        echo
        set +e
        sudo "$HOUSTON/.venv/bin/python3" \
            "$REPO/tools/boot_nonsecure_probe.py" \
            --houston-dir "$HOUSTON" \
            --payload "$NATIVE_TRIPLE_RESTORE_PAYLOAD" \
            --listen-ep1 25 \
            --output "/tmp/exynos9825_ubstage_native_triple_restore.bin"
        probe_rc=$?
        set -e
        case "$probe_rc" in
            0) ;;
            130|143) exit "$probe_rc" ;;
            *)
                echo "Native triple-restore run exited with status $probe_rc; count the EUN3REC* records above." >&2
                ;;
        esac
        cat <<EOF

This command did not write the BOOTLOADER partition. Report which EUN3REC*
records arrived AND what the screen did.
EOF
        ;;
    trace)
        cat <<EOF

The cross-EUB PMU trace is retired for this board.

The physical two-session calibration wrote and read back PMC1/PMC2 plus two
iRAM markers in session 1. A fresh EUB session then returned PMU=NO and
iRAM=NO. Therefore a later zero trace cannot say whether the u-boot trampoline
ran, and repeating it would not add evidence.

This action did not enter EUB, read UFS, write UFS, or issue an OTP command.

The diagnostic currently expected on UFS remains:
  $IMAGE
EOF
        ;;
    calibrate-retention)
        mark_payload="$REPO/build/epbl_retention_mark_probe.bin"
        read_payload="$REPO/build/epbl_retention_read_probe.bin"
        mark_output="/tmp/exynos9825_retention_mark.bin"
        read_output="/tmp/exynos9825_retention_read.bin"
        make -C "$REPO" \
            build/epbl_retention_mark_probe.bin \
            build/epbl_retention_read_probe.bin
        cat <<EOF

Volatile checkpoint retention calibration using two fresh EUB sessions.

Session 1 writes and reads back PMC1/PMC2 in PMU scratch plus IRAMCAL1/IRAMCAL2
at iRAM 0x02038800. After that EUB session closes, session 2 only reads those
locations. Re-enter EUB without removing battery or board power if possible.

This action does not access UFS and does not issue an OTP command.

No BOOTLOADER image is written by this action. The diagnostic currently on UFS
is left unchanged at:
  $IMAGE

Interpret the final RTNREAD! record as follows:
  PMU=YES   PMU can carry a checkpoint across this EUB reentry method
  iRAM=YES  iRAM can carry a checkpoint across this EUB reentry method
  both NO   neither location is a valid oracle for the preceding trigger
EOF
        echo
        echo "== sudo authentication (before the first 6.5 second EUB window) =="
        authenticate_sudo
        echo
        echo "Session 1: enter EUB only after the waiting line appears."
        sudo "$HOUSTON/.venv/bin/python3" \
            "$REPO/tools/boot_nonsecure_probe.py" \
            --houston-dir "$HOUSTON" \
            --payload "$mark_payload" \
            --output "$mark_output"
        wait_for_eub_disconnect
        echo "Session 2: enter EUB again only after the waiting line appears."
        sudo "$HOUSTON/.venv/bin/python3" \
            "$REPO/tools/boot_nonsecure_probe.py" \
            --houston-dir "$HOUSTON" \
            --payload "$read_payload" \
            --output "$read_output"
        ;;
    *)
        usage
        ;;
esac
