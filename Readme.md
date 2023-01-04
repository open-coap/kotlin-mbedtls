Kotlin + mbedtls integration
==========================


![Maven Central](https://img.shields.io/maven-central/v/io.github.open-coap/kotlin-mbedtls)
[![License](https://img.shields.io/badge/license-Apache%202.0-brightgreen.svg)](LICENSE)

Integration with mbedtls library to provide DTLS protocol into jvm ecosystem.

## Features:

- Client DTLS with PSK authentication
- DTLS CID support (RFC 9146)

## Usage:

**Gradle**

```kotlin
dependencies {
    implementation("io.github.open-coap:kotlin-mbedtls:[VERSION]")
}
```

**Maven**

```xml

<dependency>
    <groupId>io.github.open-coap</groupId>
    <artifactId>kotlin-mbedtls</artifactId>
    <version>[VERSION]</version>
</dependency>
```

DTLS client:

```kotlin
// create mbedtls SSL configuration with PSK credentials
val conf: SslConfig = SslConfig.client(
    PskAuth(
        pskId = "device-007",
        pskSecret = byteArrayOf(0x01, 0x02)
    )
)
// create client and initiate handshake
val client: DtlsTransmitter = DtlsTransmitter
    .connect(InetSocketAddress(InetAddress.getLocalHost(), 1_5684), conf, 6001)
    .get(10, TimeUnit.SECONDS)

// send and receive packets
val sendResult: CompletableFuture<Boolean> = client.send("hello")
val receive: CompletableFuture<ByteArray> = client.receive(timeout = Duration.ofSeconds(2))

// . . . 

// optionally, it is possible to save session before closing client, it could be later reloaded
// note: after saving session, it is not possible to is client
val storedSession: ByteArray = client.saveSession()
client.close()

// close SSL configuration:
// - make sure to close it before GC to avoid native memory leak
// - close it only after client is closed
conf.close()
```

## Supported OS

Precompiled:

- Linux (x86-64)
- Apple Mac (intel and arm)

## Development

### Useful commands

- `./gradlew build -i`             compile and test
- `./gradlew publishToMavenLocal`  publish artifact to local maven repository
- `./gradlew currentVersion`       show current version
- `./gradlew ktlintFormat`         format kotlin files

- `./gradlew release`              create next tag in Git and push to origin
- `./gradlew currentVersion`       print current version
- `./gradlew dependencyUpdates`    determine which dependencies have updates
- `./gradlew useLatestVersions`    update dependencies to the latest available versions

### Build mbedtls binaries

Linux (x86_64):

`./compileMbedtls.sh`

Mac (intel and arm):

`LDFLAGS='-arch x86_64 -arch arm64' CFLAGS='-O2 -arch x86_64 -arch arm64' DLEXT=dylib OSARCH=darwin ./compileMbedtls.sh`

Cross compiling for linux (x86_64):

- `docker run -it -v$(pwd):/work --rm dockcross/manylinux_2_28-x64 ./compileMbedtls.sh`
