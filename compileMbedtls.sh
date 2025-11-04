#!/bin/bash
set -euo pipefail

DEFAULT_MBEDTLS_VERSION=4.0.0
MBEDTLS_VERSION=${MBEDTLS_VERSION:-$DEFAULT_MBEDTLS_VERSION}
BUILD_DIR=mbedtls-lib/build/mbedtls-${MBEDTLS_VERSION}
DLEXT="${DLEXT:-so}"
OSARCH="${OSARCH:-linux-x86-64}"
CC="${CC:-gcc}"
LDFLAGS="${LDFLAGS:-}"
OBJEXT="${OBJEXT:-o}"
CMAKE_EXTRA="${CMAKE_EXTRA:-}"

# prepare build directory
mkdir -p mbedtls-lib/build
rm -rf ${BUILD_DIR}

# Clone the repository for MbedTLS 4.0.0+
echo "Cloning MbedTLS ${MBEDTLS_VERSION}..."
git clone --depth 1 --branch v${MBEDTLS_VERSION} https://github.com/Mbed-TLS/mbedtls.git ${BUILD_DIR}

# Initialize submodules recursively
echo "Initializing all submodules recursively..."
(cd ${BUILD_DIR} && git submodule update --init --recursive --depth 1)

# install python requirements
python3 -m pip install -r ${BUILD_DIR}/scripts/basic.requirements.txt

# Add framework to Python path if it exists (needed for MbedTLS 3.6.0+)
if [ -d "${BUILD_DIR}/framework" ]; then
    export PYTHONPATH="${BUILD_DIR}/framework:${PYTHONPATH:-}"
fi

# configure
python3 ${BUILD_DIR}/scripts/config.py -f "${BUILD_DIR}/include/mbedtls/mbedtls_config.h" unset MBEDTLS_SSL_MAX_FRAGMENT_LENGTH
python3 ${BUILD_DIR}/scripts/config.py -f "${BUILD_DIR}/include/mbedtls/mbedtls_config.h" set MBEDTLS_SSL_DTLS_CONNECTION_ID

# Run cmake configuration
cmake -S "${BUILD_DIR}" -B "${BUILD_DIR}"/build -DCMAKE_POSITION_INDEPENDENT_CODE=ON -DCMAKE_BUILD_TYPE=Release ${CMAKE_EXTRA}

cmake --build "${BUILD_DIR}"/build --target lib

# create single shared library
LIB_DIR="mbedtls-lib/bin/$OSARCH"
mkdir -p ${LIB_DIR}
rm -f ${LIB_DIR}/* 2>/dev/null || true

$CC -shared \
    ${BUILD_DIR}/build/library/CMakeFiles/mbedtls.dir/*.${OBJEXT} \
    ${BUILD_DIR}/build/library/CMakeFiles/mbedx509.dir/*.${OBJEXT} \
    ${BUILD_DIR}/build/tf-psa-crypto/core/CMakeFiles/tfpsacrypto.dir/*.${OBJEXT} \
    ${BUILD_DIR}/build/tf-psa-crypto/drivers/builtin/CMakeFiles/builtin.dir/src/*.${OBJEXT} \
    -o ${LIB_DIR}/libmbedtls-${MBEDTLS_VERSION}.${DLEXT} ${LDFLAGS}

# generate kotlin object with memory sizes
gcc mbedtls-lib/mbedtls_sizeof_generator.c \
    -I${BUILD_DIR}/include \
    -I${BUILD_DIR}/tf-psa-crypto/include \
    -I${BUILD_DIR}/tf-psa-crypto/drivers/builtin/include \
    -o mbedtls-lib/build/mbedtls_sizeof_generator
./mbedtls-lib/build/mbedtls_sizeof_generator > kotlin-mbedtls/src/main/kotlin/org/opencoap/ssl/MbedtlsSizeOf.kt
