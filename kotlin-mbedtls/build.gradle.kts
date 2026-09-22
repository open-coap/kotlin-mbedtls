plugins {
    id("java-test-fixtures")
    id("me.champeau.jmh") version "0.7.3"
}

dependencies {
    api(project(":mbedtls-lib"))

    api("org.slf4j:slf4j-api:2.0.19")
    api("net.java.dev.jna:jna:5.19.1")

    // TESTS
    testFixturesApi("org.bouncycastle:bcpkix-jdk18on:1.86")

    testImplementation("org.junit.jupiter:junit-jupiter-api:6.1.3")
    testRuntimeOnly("org.junit.jupiter:junit-jupiter-engine:6.1.3")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher:1.14.4")
    testImplementation("org.awaitility:awaitility-kotlin:4.3.0")
    testImplementation("ch.qos.logback:logback-classic:1.6.3")
    testImplementation("io.mockk:mockk:1.14.11")
}

tasks.test {
    useJUnitPlatform()
    // On Windows, native libraries must be found via PATH or explicitly set, as dynamic linking is used to load them.
    if (System.getProperty("os.name").lowercase().contains("win")) {
        val osArch = "win32-x86-64"
        systemProperty("jna.library.path", file("../mbedtls-lib/bin/$osArch").absolutePath)
    }
}

jmh {
    failOnError.set(true)
    // Read -PjmhInclude(comma separated)
    val includeProp = findProperty("jmhIncludes")?.toString()

    if (!includeProp.isNullOrBlank()) {
        includes.set(includeProp.split(',').map { it.trim() }.filter { it.isNotEmpty() })
    }
}
