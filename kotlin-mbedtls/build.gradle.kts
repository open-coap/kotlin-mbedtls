plugins {
    id("java-test-fixtures")
    id("me.champeau.jmh") version "0.7.2"
}

dependencies {
    api(project(":mbedtls-lib"))

    api(platform("org.jetbrains.kotlin:kotlin-bom"))
    api("org.jetbrains.kotlin:kotlin-stdlib-jdk8")

    api("org.slf4j:slf4j-api:2.0.16")
    api("net.java.dev.jna:jna:5.15.0")

    // TESTS
    testFixturesApi("org.bouncycastle:bcpkix-jdk15on:1.70")

    testImplementation("org.junit.jupiter:junit-jupiter-api:5.11.2")
    testRuntimeOnly("org.junit.jupiter:junit-jupiter-engine:5.11.2")
    testImplementation("org.awaitility:awaitility-kotlin:4.2.2")
    testImplementation("ch.qos.logback:logback-classic:1.3.14")
    testImplementation("org.bouncycastle:bcpkix-jdk15on:1.70")
    testImplementation("io.mockk:mockk:1.13.13")
}

tasks.test {
    useJUnitPlatform()
}
