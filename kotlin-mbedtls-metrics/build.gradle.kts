dependencies {
    api(project(":kotlin-mbedtls"))

    api(platform("org.jetbrains.kotlin:kotlin-bom"))
    api("org.jetbrains.kotlin:kotlin-stdlib-jdk8")

    implementation("io.micrometer:micrometer-core:1.13.0")

    // TESTS
    testImplementation(testFixtures(project(":kotlin-mbedtls")))
    testImplementation("org.junit.jupiter:junit-jupiter-api:5.10.2")
    testRuntimeOnly("org.junit.jupiter:junit-jupiter-engine:5.10.2")
    testImplementation("org.awaitility:awaitility-kotlin:4.2.1")
    testImplementation("ch.qos.logback:logback-classic:1.3.14")
}

tasks.test {
    useJUnitPlatform()
}
