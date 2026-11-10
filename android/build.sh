#!/bin/bash
# Offline APK build for the Photo Drop launcher. No Gradle required.
# Finds your Android SDK, or bootstraps a minimal one next to this repo.
#
#   bash android/build.sh
#
# SDK lookup order:
#   1. $ANDROID_SDK_ROOT / $ANDROID_HOME / $ANDROID_NDK_HOME-less default
#   2. ./android-sdk (this repo, git-ignored, 461 MB — never committed)
#   3. ~/Library/Android/sdk (macOS default), /opt/android-sdk, ~/Android/Sdk
#
# If none exists it downloads the official command-line tools and installs
# platform-34 + build-tools 34.0.0 into ./android-sdk. No Android Studio needed.
set -e
cd "$(dirname "$0")"

ZX="$PWD/lib/zxing-core-3.5.3.jar"
[ -e "$ZX" ] || { echo "missing $ZX" >&2; exit 1; }

sdk_find() {
  for d in "${ANDROID_SDK_ROOT:-}" "${ANDROID_HOME:-}" "$PWD/android-sdk" \
           "$HOME/Library/Android/sdk" "/opt/android-sdk" "$HOME/Android/Sdk"; do
    [ -n "$d" ] && [ -x "$d/build-tools/34.0.0/aapt2" ] && { echo "$d"; return 0; }
  done
  return 1
}

if SDK="$(sdk_find)"; then
  echo "using SDK: $SDK"
else
  echo "no Android SDK with build-tools 34.0.0 found."
  echo "bootstrapping ./android-sdk (command-line tools + platform 34)..."
  mkdir -p "$PWD/android-sdk/cmdline-tools"
  cd "$PWD/android-sdk/cmdline-tools"
  URL="https://dl.google.com/android/repository/commandlinetools-linux-11076708_latest.zip"
  ZIP="$PWD/cmdline-tools.zip"
  echo "  fetching $URL"
  curl -fL "$URL" -o "$ZIP"
  mkdir -p extracted
  unzip -q -o "$ZIP" -d extracted
  rm -f "$ZIP"
  if [ -d "extracted/cmdline-tools" ]; then
    mv extracted/cmdline-tools latest
  else
    mv extracted latest
  fi
  rm -rf extracted
  MGR="./latest/bin/sdkmanager"
  yes | "$MGR" --sdk_root="$PWD/.." --licenses >/dev/null 2>&1 || true
  "$MGR" --sdk_root="$PWD/.." "platforms;android-34" "build-tools;34.0.0" >/dev/null
  cd "$PWD/.."
  SDK="$PWD/android-sdk"
  echo "SDK ready: $SDK"
fi

BT="$SDK/build-tools/34.0.0"
AJAR="$SDK/platforms/android-34/android.jar"
KS="$PWD/debug.keystore"
[ -e "$AJAR" ] || { echo "missing $AJAR — install platforms;android-34" >&2; exit 1; }

rm -rf out && mkdir -p out/gen out/classes out/dex

echo "--- aapt2 compile/link"
"$BT/aapt2" compile --dir res -o out/compiled.zip
"$BT/aapt2" link -o out/base.apk -I "$AJAR" \
  --manifest AndroidManifest.xml \
  --min-sdk-version 26 --target-sdk-version 34 \
  --java out/gen out/compiled.zip

echo "--- javac"
find src out/gen -name '*.java' > out/sources.txt
javac --release 8 -cp "$AJAR:$ZX" -d out/classes @out/sources.txt

echo "--- d8"
# The ZXing jar goes in as program input, not just --lib, so its classes are
# actually present in classes.dex. Pure Java, no Android dependency.
"$BT/d8" --lib "$AJAR" --min-api 26 --output out/dex \
  $(find out/classes -name '*.class') "$ZX"

echo "--- zip/align/sign"
cp out/base.apk out/unsigned.apk
zip -j -q out/unsigned.apk out/dex/classes.dex
"$BT/zipalign" -f 4 out/unsigned.apk out/aligned.apk
[ -f "$KS" ] || keytool -genkeypair -keystore "$KS" -alias androiddebugkey \
  -storepass android -keypass android -keyalg RSA -keysize 2048 -validity 10000 \
  -dname "CN=Android Debug" -noprompt
"$BT/apksigner" sign --ks "$KS" --ks-pass pass:android --key-pass pass:android \
  --out photodrop.apk out/aligned.apk
"$BT/apksigner" verify --print-certs photodrop.apk | head -2
ls -la photodrop.apk
echo BUILD_OK
