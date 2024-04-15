plugins {
    id("me.champeau.jmh") version "0.7.2"
}

dependencies {
    api(project(":kotlin-mbedtls"))

    api(platform("org.jetbrains.kotlin:kotlin-bom"))
    api("org.jetbrains.kotlin:kotlin-stdlib-jdk8")
    api("io.netty:netty-handler:4.1.109.Final")

    // TESTS
    testImplementation(testFixtures(project(":kotlin-mbedtls")))

    testImplementation("org.junit.jupiter:junit-jupiter-api:5.10.2")
    testRuntimeOnly("org.junit.jupiter:junit-jupiter-engine:5.10.2")
    testImplementation("ch.qos.logback:logback-classic:1.3.0")
    testImplementation("org.awaitility:awaitility-kotlin:4.2.1")
    testImplementation("io.netty:netty-all:4.1.109.Final")
    testImplementation("io.mockk:mockk:1.13.10")
    testImplementation("org.assertj:assertj-core:3.25.3")
}

tasks.test {
    useJUnitPlatform()
}
