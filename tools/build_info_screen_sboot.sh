#!/usr/bin/env bash
# Build an sboot that narrates its own boot on the panel.
#
# WHAT IT ADDS
#   One call, to code Samsung already shipped. `0xc9002928` draws a block of
#   hardware identification in green -- EVT, ECT, LOT_ID, CHIP_ID, the PMIC
#   trim, the LPDDR4 vendor, process and size, CARRIER_ID, the UFS vendor and
#   firmware revision, and the warranty bit -- using the same panel printf
#   that draws the Odin screen. Nothing in a shipped build reaches it.
#
# WHERE IT STARTS
#   After drawLOGO, because before that there is no panel to draw on. The
#   BootROM, the EPBL and BL2 -- the DRAM training, the part that would be
#   most interesting to watch -- run before the display exists and can never
#   appear here. Their messages only ever go to UART.
#
# BASE
#   ecdsa_green2: our signed chain with force-green and the corrected
#   Secure Download label. This adds the info screen and nothing else.
set -euo pipefail

CUSTOM="/home/chanz22/EUB-N10/9825_customkey"
REPO="/home/chanz22/Documents/GitHub/exynos9825-payloads"
BASE="${BASE:-$CUSTOM/ecdsa_green2}"
OUTDIR="${OUTDIR:-$CUSTOM/ecdsa_green3}"

[[ -d "$BASE/sboot" ]] || { echo "error: $BASE/sboot is missing" >&2; exit 1; }

rm -rf "$OUTDIR"
mkdir -p "$OUTDIR"
cp -a "$BASE/sboot" "$OUTDIR/sboot"

python3 "$REPO/tools/sboot_patch.py" "$OUTDIR/sboot/u-boot.bin" \
    --no-eng --boot-info-screen

# build.py reassembles the stages and re-signs every block with our keys,
# so the u-boot ST2 signature covering the patch is regenerated here.
( cd "$CUSTOM" && python3 scripts/build.py s5e9825 keys "$OUTDIR" )
( cd "$CUSTOM" && python3 scripts/verify_9825.py "$OUTDIR/sboot.bin" )

echo
echo "built $OUTDIR/sboot.bin"
sha256sum "$OUTDIR/sboot.bin"

# ---------------------------------------------------------------------------
# vbmeta carries a hash descriptor over the bootloader partition, so changing
# sboot.bin invalidates it. The AVB pair has to be regenerated against THIS
# sboot, not reused from the previous build.
# ---------------------------------------------------------------------------
FW="${FW:-/home/chanz22/Documents/SAMFW.COM_SM-N975F_ZTO_N975FXXS9HWG3_fac}"
SRC="$FW/BL_N975FXXS9HWG3_CL24230781_QB68123164_REV01_user_low_ship"
AVB="$REPO/build/custom_avb_infoscreen"
STOCKDIR="$REPO/build/.stock_bl"
OUR_CM="$REPO/build/custom_cm/cm.bin"
TAR="${TAR:-$REPO/build/partial_bl/BL_ours_infoscreen.tar.md5}"

mkdir -p "$STOCKDIR"
for n in sboot.bin cm.bin keystorage.bin vbmeta.img; do
    [[ -f "$STOCKDIR/$n" ]] || lz4 -d -f "$SRC/$n.lz4" "$STOCKDIR/$n" >/dev/null
done

echo
echo "== re-rooting AVB against the new sboot =="
python3 "$REPO/tools/make_custom_avb.py" \
    --vbmeta "$STOCKDIR/vbmeta.img" \
    --keystorage "$STOCKDIR/keystorage.bin" \
    --stock-image "bootloader=$STOCKDIR/sboot.bin" \
    --stock-image "cm=$STOCKDIR/cm.bin" \
    --image "bootloader=$OUTDIR/sboot.bin" \
    --image "cm=$OUR_CM" \
    --disable-hashtree \
    --out-dir "$AVB"

echo
echo "== building the Odin tar =="
MODE=full \
OUR_SBOOT="$OUTDIR/sboot.bin" \
OUR_CM="$OUR_CM" \
OUR_KEYSTORAGE="$AVB/keystorage.bin" \
OUR_VBMETA="$AVB/vbmeta.img" \
    "$REPO/tools/build_partial_bl_tar.sh" "$TAR"

echo
python3 "$REPO/tools/check_avb_descriptors.py" \
    --vbmeta "$AVB/vbmeta.img" \
    --image "bootloader=$OUTDIR/sboot.bin" \
    --image "cm=$OUR_CM" \
    --image "keystorage=$AVB/keystorage.bin"
echo
echo "FLASH:  sudo odin4 -b $TAR"
