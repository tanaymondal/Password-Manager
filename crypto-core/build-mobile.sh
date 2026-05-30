#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"

echo "=== Building crypto-core for mobile targets ==="

# Android NDK must be set
if [ -z "${ANDROID_NDK_HOME:-}" ]; then
  echo "ERROR: ANDROID_NDK_HOME not set. Install NDK via Android Studio (SDK Manager > SDK Tools > NDK)."
  echo "  export ANDROID_NDK_HOME=\$ANDROID_HOME/ndk/<version>"
  exit 1
fi

BUILD_DIR="target/mobile"

echo "--- Building for Android (arm64-v8a) ---"
cargo ndk -t arm64-v8a -o "$BUILD_DIR/android/jni" build --release
echo "Android arm64-v8a: $BUILD_DIR/android/jni/arm64-v8a/libsecurevault_crypto_core.so"

echo "--- Building for Android (armeabi-v7a) ---"
cargo ndk -t armeabi-v7a -o "$BUILD_DIR/android/jni" build --release
echo "Android armeabi-v7a: $BUILD_DIR/android/jni/armeabi-v7a/libsecurevault_crypto_core.so"

echo "--- Building for Android (x86_64, emulator) ---"
cargo ndk -t x86_64 -o "$BUILD_DIR/android/jni" build --release
echo "Android x86_64: $BUILD_DIR/android/jni/x86_64/libsecurevault_crypto_core.so"

echo "--- Building for iOS (aarch64) ---"
cargo build --release --target aarch64-apple-ios
mkdir -p "$BUILD_DIR/ios"
cp "target/aarch64-apple-ios/release/libsecurevault_crypto_core.a" "$BUILD_DIR/ios/"
echo "iOS: $BUILD_DIR/ios/libsecurevault_crypto_core.a"

echo "--- Generating C header for iOS ---"
cargo run --bin cbindgen -- -o "$BUILD_DIR/ios/securevault_crypto_core.h" 2>/dev/null || \
  echo "WARN: cbindgen not installed. Run: cargo install cbindgen"

echo ""
echo "=== Mobile build complete ==="
echo "Android .so files:  $BUILD_DIR/android/jni/"
echo "iOS .a + .h files:  $BUILD_DIR/ios/"
echo ""
echo "To integrate into Android:"
echo "  1. Copy android/jni/ to mobile/app/src/main/jniLibs/"
echo "  2. Add JNI wrapper Kotlin class (see crypto-core/src/android/CryptoCore.kt)"
echo ""
echo "To integrate into iOS:"
echo "  1. Add .a and .h to Xcode project"
echo "  2. Add Swift wrapper (see crypto-core/src/ios/CryptoCore.swift)"
