#!/usr/bin/env bash
# Draw the blue prompt wherever you want, and find out how far the boot gets.
#
# usage: tools/build_prompt_probe_chain.sh "Starting kernel...\n\n"
#
# The relocated USB RECOVERY prompt is the only output this board reliably
# produces on the normal-boot path, so it is used as a general marker: name a
# diagnostic string and the prompt is drawn when the code printing it runs.
# Blue = reached. A crash cannot draw a prompt, so blue is never a false
# positive.
set -euo pipefail
REPO="/home/chanz22/Documents/GitHub/exynos9825-payloads"
CUSTOM="/home/chanz22/EUB-N10/9825_customkey"
CHAIN="$REPO/build/prompt_probe_chain"
MARKER="${1:?usage: $0 "'"<diagnostic string>"'"}"

mkdir -p "$CHAIN"
(
    cd "$CUSTOM"
    python3 scripts/split.py s5e9825 input "$CHAIN"
    python3 scripts/patch_9825.py "$CHAIN/sboot/u-boot.bin"
)
python3 "$REPO/tools/sboot_patch.py" "$CHAIN/sboot/u-boot.bin" \
    --normal-boot --force-secure-payload --ignore-secpayload-sentinel --prompt-after "$MARKER" --no-eng
(
    cd "$CUSTOM"
    python3 scripts/build.py s5e9825 keys "$CHAIN"
    python3 scripts/verify_9825.py "$CHAIN/sboot.bin" >/dev/null
)
echo
echo "marker: $MARKER"
sha256sum "$CHAIN/sboot.bin"
