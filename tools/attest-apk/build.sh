#!/usr/bin/env bash
# Build the RootOfTrust attestation APK by hand (no gradle).
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SDK=/opt/android-sdk
BT=$SDK/build-tools/34.0.0
JAR=$SDK/platforms/android-34/android.jar
OUT="$HERE/out"
rm -rf "$OUT"; mkdir -p "$OUT/gen" "$OUT/classes"

# 1. link resources (manifest only) -> base APK + R.java
"$BT/aapt2" link -I "$JAR" --manifest "$HERE/AndroidManifest.xml" \
    --java "$OUT/gen" -o "$OUT/base.apk"

# 2. compile java against android.jar
find "$HERE/src" "$OUT/gen" -name '*.java' > "$OUT/srcs.txt"
javac -source 17 -target 17 -cp "$JAR" -d "$OUT/classes" @"$OUT/srcs.txt"

# 3. dex
"$BT/d8" --min-api 29 --output "$OUT" $(find "$OUT/classes" -name '*.class')

# 4. add classes.dex into the apk
( cd "$OUT" && zip -q base.apk classes.dex )

# 5. align
"$BT/zipalign" -f 4 "$OUT/base.apk" "$OUT/aligned.apk"

# 6. debug key + sign
KS="$HERE/debug.keystore"
if [[ ! -f "$KS" ]]; then
    keytool -genkeypair -keystore "$KS" -storepass android -keypass android \
        -alias androiddebugkey -dname "CN=Android Debug" \
        -keyalg RSA -keysize 2048 -validity 10000 >/dev/null 2>&1
fi
"$BT/apksigner" sign --ks "$KS" --ks-pass pass:android --key-pass pass:android \
    --out "$HERE/rootoftrust.apk" "$OUT/aligned.apk"
echo
echo "built $HERE/rootoftrust.apk"
sha256sum "$HERE/rootoftrust.apk"
