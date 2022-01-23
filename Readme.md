Kotlin + mbedtls integration
==========================

Integration with mbedtls library to provide DTLS protocol into jvm ecosystem.

## Features:

- Client DTLS with PSK authentication

## Supported OS

Out of the box:
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

## Build mbedtls binaries

```
 ./compileMbedtls.sh
```
