#!/bin/bash
set -e

# Define destination directories for each architecture.
BUILD_ROOT="external/build"
BUILD_ARM64="$BUILD_ROOT/arm64"
BUILD_X86_64="$BUILD_ROOT/x86_64"

# Create directory structure for both architectures.
mkdir -p "$BUILD_ARM64/argon2/include" "$BUILD_ARM64/argon2/lib"
mkdir -p "$BUILD_ARM64/libjpeg/include" "$BUILD_ARM64/libjpeg/lib"
mkdir -p "$BUILD_ARM64/openssl/include" "$BUILD_ARM64/openssl/lib"

mkdir -p "$BUILD_X86_64/argon2/include" "$BUILD_X86_64/argon2/lib"
mkdir -p "$BUILD_X86_64/libjpeg/include" "$BUILD_X86_64/libjpeg/lib"
mkdir -p "$BUILD_X86_64/openssl/include" "$BUILD_X86_64/openssl/lib"

##########################
# Build Argon2
##########################
echo "=== Building Argon2 for arm64 ==="
pushd external/argon2
    make clean || true
    export CFLAGS="-arch arm64 -O3"
    make -j4
popd
cp external/argon2/libargon2.a "$BUILD_ARM64/argon2/lib/"
cp external/argon2/include/argon2.h "$BUILD_ARM64/argon2/include/"

echo "=== Building Argon2 for x86_64 ==="
pushd external/argon2
    make clean || true
    export CFLAGS="-arch x86_64 -O3"
    make -j4
popd
cp external/argon2/libargon2.a "$BUILD_X86_64/argon2/lib/"
cp external/argon2/include/argon2.h "$BUILD_X86_64/argon2/include/"

##########################
# Build libjpeg (libjpeg-turbo)
##########################
echo "=== Building libjpeg for arm64 ==="
pushd external/libjpeg
    mkdir -p build_arm64 && cd build_arm64
    cmake -G"Unix Makefiles" \
          -DCMAKE_BUILD_TYPE=Release \
          -DENABLE_SHARED=OFF \
          -DCMAKE_OSX_ARCHITECTURES=arm64 \
          -DCMAKE_C_FLAGS="-arch arm64" \
          -DCMAKE_INSTALL_PREFIX=./install ..
    make -j4
    make install
    cd ..
popd
cp external/libjpeg/build_arm64/install/lib/libjpeg.a "$BUILD_ARM64/libjpeg/lib/"
cp -R external/libjpeg/build_arm64/install/include/* "$BUILD_ARM64/libjpeg/include/"

echo "=== Building libjpeg for x86_64 ==="
pushd external/libjpeg
    mkdir -p build_x86_64 && cd build_x86_64
    cmake -G"Unix Makefiles" \
          -DCMAKE_BUILD_TYPE=Release \
          -DENABLE_SHARED=OFF \
          -DCMAKE_OSX_ARCHITECTURES=x86_64 \
          -DCMAKE_C_FLAGS="-arch x86_64" \
          -DCMAKE_INSTALL_PREFIX=./install ..
    make -j4
    make install
    cd ..
popd
cp external/libjpeg/build_x86_64/install/lib/libjpeg.a "$BUILD_X86_64/libjpeg/lib/"
cp -R external/libjpeg/build_x86_64/install/include/* "$BUILD_X86_64/libjpeg/include/"

##########################
# Build OpenSSL (minimal libcrypto)
##########################
echo "=== Building OpenSSL for arm64 ==="
pushd external/openssl
    make clean || true
    ./Configure darwin64-arm64-cc no-shared no-ssl no-dtls no-comp no-engine no-tests no-asm
    make -j4
popd
cp external/openssl/libcrypto.a "$BUILD_ARM64/openssl/lib/"
cp -R external/openssl/include/openssl "$BUILD_ARM64/openssl/include/"

echo "=== Building OpenSSL for x86_64 ==="
pushd external/openssl
    make clean || true
    ./Configure darwin64-x86_64-cc no-shared no-ssl no-dtls no-comp no-engine no-tests no-asm
    make -j4
popd
cp external/openssl/libcrypto.a "$BUILD_X86_64/openssl/lib/"
cp -R external/openssl/include/openssl "$BUILD_X86_64/openssl/include/"

echo "External libraries built for both arm64 and x86_64."
