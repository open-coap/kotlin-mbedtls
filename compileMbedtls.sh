#!/bin/bash
set -euo pipefail

DEFAULT_MBEDTLS_VERSION=3.6.3
MBEDTLS_VERSION=${MBEDTLS_VERSION:-$DEFAULT_MBEDTLS_VERSION}
BUILD_DIR=mbedtls-lib/build/mbedtls-${MBEDTLS_VERSION}
DLEXT="${DLEXT:-so}"
OSARCH="${OSARCH:-linux-x86-64}"
CC="${CC:-gcc}"
LDFLAGS="${LDFLAGS:-}"

# download
mkdir -p mbedtls-lib/build
wget -N https://github.com/Mbed-TLS/mbedtls/archive/refs/tags/v${MBEDTLS_VERSION}.tar.gz -O mbedtls-lib/build/mbedtls.tar.gz
rm -rf ${BUILD_DIR}
tar -xf mbedtls-lib/build/mbedtls.tar.gz -C mbedtls-lib/build/ --no-same-owner

# Download framework for MbedTLS 3.6.0+ if needed
if [ ! -d "${BUILD_DIR}/framework" ] && [ -f "${BUILD_DIR}/scripts/config.py" ]; then
    echo "Downloading mbedtls-framework for MbedTLS ${MBEDTLS_VERSION}..."
    git clone --depth 1 https://github.com/Mbed-TLS/mbedtls-framework.git ${BUILD_DIR}/framework || true
fi

# install python requirements
python3 -m pip install -r ${BUILD_DIR}/scripts/basic.requirements.txt

# Add framework to Python path if it exists (needed for MbedTLS 3.6.0+)
if [ -d "${BUILD_DIR}/framework" ]; then
    export PYTHONPATH="${BUILD_DIR}/framework:${PYTHONPATH:-}"
fi

# configure
chmod +x ${BUILD_DIR}/scripts/config.pl
${BUILD_DIR}/scripts/config.pl -f "${BUILD_DIR}/include/mbedtls/mbedtls_config.h" unset MBEDTLS_SSL_MAX_FRAGMENT_LENGTH
${BUILD_DIR}/scripts/config.pl -f "${BUILD_DIR}/include/mbedtls/mbedtls_config.h" set MBEDTLS_SSL_DTLS_CONNECTION_ID

## compile
export SHARED=true
(cd ${BUILD_DIR} && make lib)

# create single shared library
LIB_DIR="mbedtls-lib/bin/$OSARCH"
mkdir -p ${LIB_DIR}
rm -f ${LIB_DIR}/* 2>/dev/null || true
$CC -shared ${BUILD_DIR}/library/*.o -o ${LIB_DIR}/libmbedtls-${MBEDTLS_VERSION}.${DLEXT} ${LDFLAGS}

# generate kotlin object with memory sizes
gcc mbedtls-lib/mbedtls_sizeof_generator.c -I${BUILD_DIR}/include -I${BUILD_DIR}/crypto/include -o mbedtls-lib/build/mbedtls_sizeof_generator
./mbedtls-lib/build/mbedtls_sizeof_generator > kotlin-mbedtls/src/main/kotlin/org/opencoap/ssl/MbedtlsSizeOf.kt
