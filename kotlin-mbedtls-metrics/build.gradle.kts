import org.jetbrains.kotlin.gradle.tasks.KotlinCompile

plugins {
    id("org.jetbrains.kotlin.jvm") version "1.7.22"
    id("org.jlleitschuh.gradle.ktlint") version "11.0.0"
    id("com.adarshr.test-logger") version "3.2.0"
    id("io.gitlab.arturbosch.detekt") version "1.22.0"
}

dependencies {
    api(project(":kotlin-mbedtls"))

    api(platform("org.jetbrains.kotlin:kotlin-bom"))
    api("org.jetbrains.kotlin:kotlin-stdlib-jdk8")

    implementation("io.micrometer:micrometer-core:1.10.4")

    // TESTS
    testImplementation("org.junit.jupiter:junit-jupiter-api:5.9.1")
    testRuntimeOnly("org.junit.jupiter:junit-jupiter-engine:5.9.1")
    testImplementation("org.awaitility:awaitility-kotlin:4.2.0")
}

java {
    sourceCompatibility = JavaVersion.VERSION_1_8
    targetCompatibility = JavaVersion.VERSION_1_8
}

tasks.withType<KotlinCompile> {
    kotlinOptions.jvmTarget = "1.8"
}

tasks.test {
    useJUnitPlatform()
}

detekt {
    source = files("src/main/kotlin")
    config = files("../detekt.yml")
    buildUponDefaultConfig = true
}
