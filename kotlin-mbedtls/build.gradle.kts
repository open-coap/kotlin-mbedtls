plugins {
    id("java-test-fixtures")
    id("me.champeau.jmh") version "0.7.2"
}

dependencies {
    api(project(":mbedtls-lib"))

    api(platform("org.jetbrains.kotlin:kotlin-bom"))
    api("org.jetbrains.kotlin:kotlin-stdlib-jdk8")

    api("org.slf4j:slf4j-api:2.0.13")
    api("net.java.dev.jna:jna:5.14.0")

    // TESTS
    testFixturesApi("org.bouncycastle:bcpkix-jdk15on:1.70")

    testImplementation("org.junit.jupiter:junit-jupiter-api:5.10.2")
    testRuntimeOnly("org.junit.jupiter:junit-jupiter-engine:5.10.2")
    testImplementation("org.awaitility:awaitility-kotlin:4.2.1")
    testImplementation("ch.qos.logback:logback-classic:1.3.0")
    testImplementation("org.bouncycastle:bcpkix-jdk15on:1.70")
    testImplementation("io.mockk:mockk:1.13.10")
}

tasks.test {
    useJUnitPlatform()
}
