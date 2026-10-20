#!/usr/bin/env bash
# Build a BL tar carrying Samsung's bootloader components EXCEPT the two that
# must stay ours.
#
# WHY
#   Skipping BL entirely to protect our sboot.bin and cm.bin also left
#   keystorage.bin, uh.bin, param.bin, up_param.bin and vbmeta.img out. The
#   first of those is ST2-signed and our bootloader verifies it against OUR
#   key, so Samsung's copy fails, keystorage never loads, PO_AVB_KEY is
#   missing and AVB reports
#
#       Error while checking public key used to sign data. (2)
#
#   which reads like a vbmeta fault and is not one.
#
# WHAT GOES IN
#   keystorage.bin  re-signed with our ST2-TEE key
#   uh.bin          Samsung's, unchanged  (f_load_hypervisor goes through
#                   check_signature, which our eng build returns 0 from)
#   param.bin       Samsung's, unchanged
#   up_param.bin    Samsung's, unchanged
#   vbmeta.img      Samsung's, unchanged
#
# WHAT STAYS OUT
#   sboot.bin       ours is on the device and the BootROM accepts only ours
#   cm.bin          ours is on the device; Samsung's would fail the LDFW check
set -euo pipefail

REPO="/home/chanz22/Documents/GitHub/exynos9825-payloads"
FW="${FW:-/home/chanz22/Documents/SAMFW.COM_SM-N975F_ZTO_N975FXXS9HWG3_fac}"
WORK="$REPO/build/partial_bl"
OUT="${1:-$REPO/build/partial_bl/BL_custom_keystorage.tar.md5}"

SRC_BL="$(ls "$FW"/BL_*.tar.md5)"
# MODE=partial  Samsung's components with our keystorage; sboot and cm left
#               on the device untouched. Use when ours are already flashed.
# MODE=full     everything the BOOTLOADER chain needs, ours included, in one
#               tar. Use on a fresh board: one Odin step instead of three,
#               so there is no window where our cm.bin sits under a stock
#               sboot, which does not boot.
MODE="${MODE:-partial}"
OUR_SBOOT="${OUR_SBOOT:-/home/chanz22/EUB-N10/9825_customkey/ecdsa_eng/sboot.bin}"
OUR_CM="${OUR_CM:-$REPO/build/custom_cm/cm.bin}"

case "$MODE" in
    partial)
        KEEP=(param.bin.lz4 up_param.bin.lz4 keystorage.bin.lz4 uh.bin.lz4 vbmeta.img.lz4)
        DROP=(sboot.bin.lz4 cm.bin.lz4)
        ;;
    full)
        KEEP=(sboot.bin.lz4 param.bin.lz4 up_param.bin.lz4 cm.bin.lz4 keystorage.bin.lz4 uh.bin.lz4 vbmeta.img.lz4)
        DROP=()
        ;;
    *) echo "error: MODE must be partial or full" >&2; exit 2 ;;
esac

command -v lz4 >/dev/null || { echo "error: lz4 is not installed" >&2; exit 1; }

rm -rf "$WORK"; mkdir -p "$WORK/stage"
echo "== source =="
echo "  $SRC_BL"

echo
echo "== extracting =="
tar xf "$SRC_BL" -C "$WORK/stage"
( cd "$WORK/stage" && ls -1 )

echo
echo "== re-signing keystorage.bin with our ST2-TEE key =="
lz4 -d -f "$WORK/stage/keystorage.bin.lz4" "$WORK/keystorage.stock.bin" >/dev/null
python3 "$REPO/tools/resign_st2_container.py" \
    "$WORK/keystorage.stock.bin" "$WORK/keystorage.bin"
# Match the frame Samsung ships: content size present, 4 MB blocks.
lz4 -9 -f --content-size -B6 "$WORK/keystorage.bin" "$WORK/stage/keystorage.bin.lz4" >/dev/null
echo "  frame header stock  : $(xxd -p -l 7 "$WORK/keystorage.stock.lz4" 2>/dev/null || xxd -p -l 7 <(tar xOf "$SRC_BL" keystorage.bin.lz4))"
echo "  frame header ours   : $(xxd -p -l 7 "$WORK/stage/keystorage.bin.lz4")"

if [[ "$MODE" == full ]]; then
    echo
    echo "== substituting our sboot and our cm =="
    for pair in "$OUR_SBOOT:sboot.bin" "$OUR_CM:cm.bin"; do
        src="${pair%%:*}"; name="${pair##*:}"
        [[ -f "$src" ]] || { echo "error: missing $src" >&2; exit 1; }
        lz4 -9 -f --content-size -B6 "$src" "$WORK/stage/$name.lz4" >/dev/null
        echo "  $name  <- $src  ($(stat -c%s "$src") bytes)"
    done
fi

echo
echo "== dropping what must stay ours =="
if [[ ${#DROP[@]} -eq 0 ]]; then echo "  (nothing: MODE=full ships the whole chain)"; else
    for f in "${DROP[@]}"; do rm -f "$WORK/stage/$f"; echo "  out: $f"; done
fi

echo
echo "== building the tar =="
TARNAME="$(basename "${OUT%.md5}")"
( cd "$WORK/stage" && tar cf "$WORK/$TARNAME" "${KEEP[@]}" )
tar tvf "$WORK/$TARNAME" | awk '{printf "  %-24s %12s\n", $NF, $3}'

# Samsung's .tar.md5 is the tar with `md5sum` output appended as text.
( cd "$WORK" && md5sum "$TARNAME" >> "$TARNAME" && mv "$TARNAME" "$(basename "$OUT")" )
mkdir -p "$(dirname "$OUT")"
[[ "$WORK/$(basename "$OUT")" == "$OUT" ]] || mv "$WORK/$(basename "$OUT")" "$OUT"

echo
echo "wrote $OUT"
sha256sum "$OUT"
echo
echo "flash it with:"
echo "  sudo odin4 -b $OUT"
