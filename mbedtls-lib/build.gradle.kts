import java.net.HttpURLConnection
import java.net.URI
import java.security.MessageDigest
import java.util.zip.ZipInputStream

plugins {
    id("java-library")
}

// Precompiled binaries change only when mbedtls is recompiled, which happens rarely. Hence this
// module is versioned independently from the kotlin modules, see `mbedtlsLibVersion` in
// `gradle.properties`.
version = providers.gradleProperty("mbedtlsLibVersion").get()

sourceSets.main {
    resources.srcDirs("bin")
}

val binDir = layout.projectDirectory.dir("bin")
val artifact = "$name:$version"
val releasedArtifactUrl = "https://repo1.maven.org/maven2/${project.group.toString().replace('.', '/')}/$name/$version/$name-$version.jar"
val publishDecisionFile = layout.buildDirectory.file("publish-decision.txt")
val forcePublish = providers.gradleProperty("publishMbedtlsLib").map(String::toBoolean)

fun sha256(bytes: ByteArray): String = MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it) }

fun localBinaries(): Map<String, String> = binDir.asFileTree.files.associate { it.relativeTo(binDir.asFile).invariantSeparatorsPath to sha256(it.readBytes()) }

// Returns digests of the binaries of an already released version, or null when it is not released yet
fun releasedBinaries(): Map<String, String>? {
    val connection = URI(releasedArtifactUrl).toURL().openConnection() as HttpURLConnection
    connection.connectTimeout = 30_000
    connection.readTimeout = 30_000
    try {
        if (connection.responseCode == HttpURLConnection.HTTP_NOT_FOUND) return null
        check(connection.responseCode == HttpURLConnection.HTTP_OK) {
            "Unable to verify $releasedArtifactUrl, got HTTP ${connection.responseCode}"
        }

        return connection.inputStream.use { input ->
            ZipInputStream(input).use { zip ->
                generateSequence { zip.nextEntry }
                    .filterNot { it.isDirectory || it.name.startsWith("META-INF/") }
                    .associate { it.name to sha256(zip.readBytes()) }
            }
        }
    } finally {
        connection.disconnect()
    }
}

val verifyReleasedBinaries by tasks.registering {
    group = "publishing"
    description = "Verifies if mbedtls binaries of the current version are already released to Maven Central"
    inputs.dir(binDir)
    inputs.property("version", version.toString())
    outputs.file(publishDecisionFile)
    onlyIf { !forcePublish.isPresent }

    doLast {
        val released = releasedBinaries()
        val isReleased = when {
            released == null -> false
            released == localBinaries() -> true
            else -> throw GradleException(
                "mbedtls binaries differ from already released $artifact. " +
                    "Bump `mbedtlsLibVersion` in `gradle.properties`, released versions are immutable."
            )
        }

        if (isReleased) logger.lifecycle("$artifact is already released, skipping its publication")
        publishDecisionFile.get().asFile.writeText(if (isReleased) "skip" else "publish")
    }
}

tasks.withType<PublishToMavenRepository>().configureEach {
    dependsOn(verifyReleasedBinaries)
    onlyIf { forcePublish.orNull ?: (publishDecisionFile.get().asFile.readText() == "publish") }
}

// Same as the bash one-liner in `gradle.properties`: sha256 of sorted `sha256sum` output lines
fun binariesHash(): String = sha256(localBinaries().toSortedMap().entries.joinToString("") { "${it.value}  ${it.key}\n" }.toByteArray())

val verifyBinariesHash by tasks.registering {
    group = "verification"
    description = "Verifies that mbedtls binaries match `mbedtlsLibBinariesSha256` in `gradle.properties`"
    val libVersion = version.toString()
    val recorded = providers.gradleProperty("mbedtlsLibBinariesSha256")
    inputs.dir(binDir)
    inputs.property("version", libVersion)
    inputs.property("recorded", recorded)

    doLast {
        val (recordedVersion, recordedHash) = recorded.get().split(':', limit = 2)
        val actualHash = binariesHash()
        val binariesChanged = actualHash != recordedHash
        val versionChanged = libVersion != recordedVersion

        if (binariesChanged && !versionChanged) {
            throw GradleException(
                "mbedtls binaries changed. Bump `mbedtlsLibVersion` in `gradle.properties`, " +
                    "then set `mbedtlsLibBinariesSha256=<new-version>:$actualHash`"
            )
        }
        if (binariesChanged || versionChanged) {
            throw GradleException("Set `mbedtlsLibBinariesSha256=$libVersion:$actualHash` in `gradle.properties`")
        }
    }
}

tasks.named("check") {
    dependsOn(verifyBinariesHash)
}
