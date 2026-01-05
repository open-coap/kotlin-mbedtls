dependencies {
    api(project(":kotlin-mbedtls"))

    implementation("io.micrometer:micrometer-core:1.16.1")

    // TESTS
    testImplementation(testFixtures(project(":kotlin-mbedtls")))
    testImplementation("org.junit.jupiter:junit-jupiter-api:5.14.1")
    testRuntimeOnly("org.junit.jupiter:junit-jupiter-engine:5.14.1")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher:1.13.4")
    testImplementation("org.awaitility:awaitility-kotlin:4.3.0")
    testImplementation("ch.qos.logback:logback-classic:1.5.23")
}

tasks.test {
    useJUnitPlatform()
    // On Windows, native libraries must be found via PATH or explicitly set, as dynamic linking is used to load them.
    if (System.getProperty("os.name").lowercase().contains("win")) {
        val osArch = "win32-x86-64"
        systemProperty("jna.library.path", file("../mbedtls-lib/bin/$osArch").absolutePath)
    }
}
