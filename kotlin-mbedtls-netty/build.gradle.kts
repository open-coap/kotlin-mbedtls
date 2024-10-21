plugins {
    id("me.champeau.jmh") version "0.7.2"
}

dependencies {
    api(project(":kotlin-mbedtls"))

    api("io.netty:netty-handler:4.1.114.Final")

    // TESTS
    testImplementation(testFixtures(project(":kotlin-mbedtls")))

    testImplementation("org.junit.jupiter:junit-jupiter-api:5.11.2")
    testRuntimeOnly("org.junit.jupiter:junit-jupiter-engine:5.11.2")
    testImplementation("ch.qos.logback:logback-classic:1.3.14")
    testImplementation("org.awaitility:awaitility-kotlin:4.2.2")
    testImplementation("io.netty:netty-all:4.1.114.Final")
    testImplementation("io.mockk:mockk:1.13.13")
    testImplementation("org.assertj:assertj-core:3.26.3")
}

tasks.test {
    useJUnitPlatform()
}
