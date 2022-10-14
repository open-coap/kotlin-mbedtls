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
- MAC (x86-64)

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


- `./compileMbedtls.sh`            clone and compile mbedtls


- `./gradlew release`              create next tag in Git and push to origin
- `./gradlew currentVersion`       print current version
