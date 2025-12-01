plugins {
    id("java-test-fixtures")
    id("me.champeau.jmh") version "0.7.3"
}

dependencies {
    api(project(":mbedtls-lib"))

    api("org.slf4j:slf4j-api:2.0.17")
    api("net.java.dev.jna:jna:5.17.0")

    // TESTS
    testFixturesApi("org.bouncycastle:bcpkix-jdk15on:1.70")

    testImplementation("org.junit.jupiter:junit-jupiter-api:5.13.4")
    testRuntimeOnly("org.junit.jupiter:junit-jupiter-engine:5.13.4")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher:1.13.4")
    testImplementation("org.awaitility:awaitility-kotlin:4.3.0")
    testImplementation("ch.qos.logback:logback-classic:1.5.18")
    testImplementation("org.bouncycastle:bcpkix-jdk15on:1.70")
    testImplementation("io.mockk:mockk:1.14.5")
}

tasks.test {
    useJUnitPlatform()
}

jmh {
    failOnError.set(true)
    // Read -PjmhInclude(comma separated)
    val includeProp = findProperty("jmhIncludes")?.toString()

    if (!includeProp.isNullOrBlank()) {
        includes.set(includeProp.split(',').map { it.trim() }.filter { it.isNotEmpty() })
    }
}
