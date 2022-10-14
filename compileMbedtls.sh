#!/bin/bash
MBEDTLS_VERSION=v3.2.0-rfc9146_2
BUILD_DIR=kotlin-mbedtls/build/mbedtls
SRC=kotlin-mbedtls/src

# clone
rm -rf ${BUILD_DIR}
mkdir -p ${BUILD_DIR}
git -C ${BUILD_DIR} clone --depth 1 --branch 'rfc9146_2' https://github.com/hannestschofenig/mbedtls.git .
git -C ${BUILD_DIR} submodule update --init --recommend-shallow

# configure
${BUILD_DIR}/scripts/config.pl -f "${BUILD_DIR}/include/mbedtls/mbedtls_config.h" unset MBEDTLS_SSL_MAX_FRAGMENT_LENGTH
${BUILD_DIR}/scripts/config.pl -f "${BUILD_DIR}/include/mbedtls/mbedtls_config.h" set MBEDTLS_SSL_DTLS_CONNECTION_ID


## compile
(cd ${BUILD_DIR} && cmake -DUSE_SHARED_MBEDTLS_LIBRARY=On -DUSE_STATIC_MBEDTLS_LIBRARY=Off -DENABLE_TESTING=OFF -DENABLE_TESTING=OFF -DENABLE_PROGRAMS=OFF -DCMAKE_BUILD_TYPE=RELEASE .)
(cd ${BUILD_DIR} && cmake --build .)


# copy binaries
# make a single dylib/so file, to enable loading from jar file
if [[ "$(uname)" == 'Darwin' ]]; then
  rm $SRC/main/resources/darwin/*
  OUTPUT_LIB="$SRC/main/resources/darwin/libmbedtls-${MBEDTLS_VERSION}.dylib"
elif [[ "$(uname)" == 'Linux' ]]; then
  rm $SRC/main/resources/linux-x86-64/*
  OUTPUT_LIB="$SRC/main/resources/linux-x86-64/libmbedtls-${MBEDTLS_VERSION}.so"
else
  echo "Failure: unsupported platform: $(uname)"
  exit 1
fi

g++ -shared ${BUILD_DIR}/library/CMakeFiles/*/*.o -o ${OUTPUT_LIB}


# generate kotlin object with memory sizes
gcc $SRC/test/c/mbedtls_sizeof_generator.c -I${BUILD_DIR}/include -I${BUILD_DIR}/crypto/include -o kotlin-mbedtls/build/mbedtls_sizeof_generator
./kotlin-mbedtls/build/mbedtls_sizeof_generator > $SRC/main/kotlin/org/opencoap/ssl/MbedtlsSizeOf.kt
