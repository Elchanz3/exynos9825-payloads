#!/usr/bin/env bash
# The differential gate, with the allowlist this project actually uses.
#
#   tools/fuse_gate.sh <u-boot.bin> [--expect-program-call]
#
# Base is the stock image after scripts/patch_9825.py, pinned by hash, so the
# eng transformation is audited once instead of per chain. Everything else
# must differ only where sboot_patch.py is allowed to write, plus the ST2
# footer, which is the re-signature and is checked by verify_9825.py and by
# tools/make_minimal_epbl_chain.py's own verifier.
set -euo pipefail
REPO="/home/chanz22/Documents/GitHub/exynos9825-payloads"
BASE="$REPO/build/base_eng_uboot.bin"
BASE_SHA="582f7d626d0686c71bc07abfe5a712f533c7e0de3e3b3062d23bdc708ad421fd"
ANCHOR="1d12d364cf441dfe7d5084a054691cf1c7f71e068e2470881e52ce280c7c330b"

[[ -f "$BASE" ]] || { echo "error: missing $BASE" >&2; exit 1; }
have=$(sha256sum "$BASE" | awk '{print $1}')
[[ "$have" == "$BASE_SHA" ]] || {
    echo "error: base u-boot hash is $have, pinned $BASE_SHA" >&2; exit 1; }

exec python3 "$REPO/tools/check_fuse_image_diff.py" "$1" --base "$BASE" \
    --allow 33f0:33f4 \
    --allow 3438:343c \
    --allow 34d4:34d8 \
    --allow 38f0:38f4 \
    --allow a2bd0:a2bd4 \
    --allow a61a4:a61a8 \
    --allow a61b0:a61b4 \
    --allow a6254:a6258 \
    --allow a63e4:a63e8 \
    --allow a6460:a6464 \
    --allow a64a4:a64a8 \
    --allow a64d0:a64d4 \
    --allow 17ce00:17ce40 \
    --allow 17fdf0:180000 \
    --anchor "$ANCHOR" \
    "${@:2}"
