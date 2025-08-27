plugins {
    id("me.champeau.jmh") version "0.7.3"
}

dependencies {
    api(project(":kotlin-mbedtls"))

    api("io.netty:netty-handler:4.2.4.Final")

    // TESTS
    testImplementation(testFixtures(project(":kotlin-mbedtls")))

    testImplementation("org.junit.jupiter:junit-jupiter-api:5.12.0")
    testRuntimeOnly("org.junit.jupiter:junit-jupiter-engine:5.12.0")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher:1.12.0")
    testImplementation("ch.qos.logback:logback-classic:1.3.14")
    testImplementation("org.awaitility:awaitility-kotlin:4.3.0")
    testImplementation("io.netty:netty-all:4.2.4.Final")
    testImplementation("io.mockk:mockk:1.13.16")
    testImplementation("org.assertj:assertj-core:3.27.3")
}

tasks.test {
    useJUnitPlatform()
}
