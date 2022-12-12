Kotlin + mbedtls integration
==========================

[![Release](https://jitpack.io/v/open-coap/kotlin-mbedtls.svg)](https://jitpack.io/#open-coap/kotlin-mbedtls)
[![License](https://img.shields.io/badge/license-Apache%202.0-brightgreen.svg)](LICENSE)

Integration with mbedtls library to provide DTLS protocol into jvm ecosystem.

## Features:

- Client DTLS with PSK authentication
- DTLS CID support (RFC 9146)

## Supported OS

Precompiled:
- Linux (x86-64)
- Apple Mac (intel and arm)

## Usage:

```kotlin
val clientSession: SslSession = SslConfig.client("psk-id".encodeToByteArray(), byteArrayOf(0x01, 0x02, 0x03))
    .newContext(DatagramChannelTransport.create(0, InetSocketAddress("localhost", 5684)))
    .handshake().join()

clientSession.send("request".encodeToByteArray())
val response: CompletableFuture<ByteArray> = clientSession.read()
```

## Useful commands

- `./gradlew build -i`             compile and test
- `./gradlew publishToMavenLocal`  publish artifact to local maven repository
- `./gradlew currentVersion`       show current version
- `./gradlew ktlintFormat`         format kotlin files

- `./gradlew release`              create next tag in Git and push to origin
- `./gradlew currentVersion`       print current version
- `./gradlew dependencyUpdates`    determine which dependencies have updates
- `./gradlew useLatestVersions`    update dependencies to the latest available versions

## Build mbedtls binaries

Linux (x86_64):

`./compileMbedtls.sh`

Mac (intel and arm):

`LDFLAGS='-arch x86_64 -arch arm64' CFLAGS='-O2 -arch x86_64 -arch arm64' DLEXT=dylib OSARCH=darwin ./compileMbedtls.sh`

Cross compiling for linux (x86_64):

- `docker run -it -v$(pwd):/work --rm dockcross/linux-x86_64-full ./compileMbedtls.sh`

