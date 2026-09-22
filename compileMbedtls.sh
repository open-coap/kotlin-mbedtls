#!/bin/bash
set -euo pipefail

DEFAULT_MBEDTLS_VERSION=4.2.0
MBEDTLS_VERSION=${MBEDTLS_VERSION:-$DEFAULT_MBEDTLS_VERSION}
BUILD_DIR=mbedtls-lib/build/mbedtls-${MBEDTLS_VERSION}
DLEXT="${DLEXT:-so}"
OSARCH="${OSARCH:-linux-x86-64}"
CMAKE_EXTRA="${CMAKE_EXTRA:-}"
LIB_DIR="mbedtls-lib/bin/$OSARCH"

# prepare build directory
mkdir -p mbedtls-lib/build
rm -rf ${BUILD_DIR}

# Clone the repository for MbedTLS 4.0.0+
echo "Cloning MbedTLS ${MBEDTLS_VERSION}..."
git clone --depth 1 --branch v${MBEDTLS_VERSION} --recurse-submodules --shallow-submodules https://github.com/Mbed-TLS/mbedtls.git ${BUILD_DIR}

# install python requirements
python3 -m pip install -r ${BUILD_DIR}/scripts/basic.requirements.txt

# Add framework to Python path if it exists (needed for MbedTLS 3.6.0+)
if [ -d "${BUILD_DIR}/framework" ]; then
    export PYTHONPATH="${BUILD_DIR}/framework:${PYTHONPATH:-}"
fi

# configure
MBEDTLS_CFG="${BUILD_DIR}/include/mbedtls/mbedtls_config.h"
CRYPTO_CFG="${BUILD_DIR}/tf-psa-crypto/include/psa/crypto_config.h"

python3 "${BUILD_DIR}/scripts/config.py" -f "$MBEDTLS_CFG" unset MBEDTLS_SSL_MAX_FRAGMENT_LENGTH
if grep -q '^#define MBEDTLS_SSL_MAX_FRAGMENT_LENGTH' "$MBEDTLS_CFG"; then
    echo "Configuration failed: MBEDTLS_SSL_MAX_FRAGMENT_LENGTH was not unset in $MBEDTLS_CFG"
    exit 1
fi

python3 "${BUILD_DIR}/scripts/config.py" -f "$MBEDTLS_CFG" set MBEDTLS_SSL_DTLS_CONNECTION_ID
if ! grep -q '^#define MBEDTLS_SSL_DTLS_CONNECTION_ID' "$MBEDTLS_CFG"; then
    echo "Configuration failed: MBEDTLS_SSL_DTLS_CONNECTION_ID was not set in $MBEDTLS_CFG"
    exit 1
fi

# Enable threading support
python3 "${BUILD_DIR}/scripts/config.py" -f "$CRYPTO_CFG" set MBEDTLS_THREADING_C
if ! grep -q '^#define MBEDTLS_THREADING_C' "$CRYPTO_CFG"; then
    echo "Configuration failed: MBEDTLS_THREADING_C was not set in $CRYPTO_CFG"
    exit 1
fi

python3 "${BUILD_DIR}/scripts/config.py" -f "$CRYPTO_CFG" set MBEDTLS_THREADING_PTHREAD
if ! grep -q '^#define MBEDTLS_THREADING_PTHREAD' "$CRYPTO_CFG"; then
    echo "Configuration failed: MBEDTLS_THREADING_PTHREAD was not set in $CRYPTO_CFG"
    exit 1
fi

echo "Configuring CMake..."
cmake \
  -S "${BUILD_DIR}" \
  -B "${BUILD_DIR}"/build \
  -DUSE_SHARED_MBEDTLS_LIBRARY=On \
  -DCMAKE_BUILD_TYPE=Release \
  ${CMAKE_EXTRA}

echo "Building MbedTLS..."
cmake --build "${BUILD_DIR}"/build --parallel --target lib

# create single shared library
mkdir -p ${LIB_DIR}
rm -f ${LIB_DIR}/* 2>/dev/null || true

# copy shared libraries
cp "${BUILD_DIR}/build/library/libmbedtls.${DLEXT}" "${LIB_DIR}/libmbedtls.${DLEXT}"
cp "${BUILD_DIR}/build/library/libmbedx509.${DLEXT}" "${LIB_DIR}/libmbedx509.${DLEXT}"
cp "${BUILD_DIR}/build/library/libtfpsacrypto"*.${DLEXT} "${LIB_DIR}/libtfpsacrypto.${DLEXT}"

# generate kotlin object with memory sizes
gcc mbedtls-lib/mbedtls_sizeof_generator.c \
    -I${BUILD_DIR}/include \
    -I${BUILD_DIR}/tf-psa-crypto/include \
    -I${BUILD_DIR}/tf-psa-crypto/drivers/builtin/include \
    -o mbedtls-lib/build/mbedtls_sizeof_generator
./mbedtls-lib/build/mbedtls_sizeof_generator > kotlin-mbedtls/src/main/kotlin/org/opencoap/ssl/MbedtlsSizeOf.kt
