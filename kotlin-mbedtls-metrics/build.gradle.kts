dependencies {
    api(project(":kotlin-mbedtls"))

    implementation("io.micrometer:micrometer-core:1.15.4")

    // TESTS
    testImplementation(testFixtures(project(":kotlin-mbedtls")))
    testImplementation("org.junit.jupiter:junit-jupiter-api:5.13.4")
    testRuntimeOnly("org.junit.jupiter:junit-jupiter-engine:5.13.4")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher:1.13.4")
    testImplementation("org.awaitility:awaitility-kotlin:4.3.0")
    testImplementation("ch.qos.logback:logback-classic:1.5.18")
}

tasks.test {
    useJUnitPlatform()
}
