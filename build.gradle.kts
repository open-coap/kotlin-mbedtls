plugins {
    id("org.jetbrains.kotlin.jvm") version "1.5.31"
    id("java-library")
}

repositories {
    mavenCentral()
}

dependencies {
    implementation(platform("org.jetbrains.kotlin:kotlin-bom"))
    implementation("org.jetbrains.kotlin:kotlin-stdlib-jdk8")

    implementation("org.slf4j:slf4j-api:1.7.32")
    implementation("net.java.dev.jna:jna:5.10.0")


    // TESTS
    testImplementation("org.jetbrains.kotlin:kotlin-test")
    testImplementation("ch.qos.logback:logback-classic:1.2.7")
}
