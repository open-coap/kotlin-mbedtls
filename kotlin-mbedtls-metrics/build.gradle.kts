import org.jetbrains.kotlin.gradle.tasks.KotlinCompile
import org.jlleitschuh.gradle.ktlint.KtlintExtension

dependencies {
    api(project(":kotlin-mbedtls"))

    api(platform("org.jetbrains.kotlin:kotlin-bom"))
    api("org.jetbrains.kotlin:kotlin-stdlib-jdk8")

    implementation("io.micrometer:micrometer-core:1.11.2")

    // TESTS
    testImplementation(testFixtures(project(":kotlin-mbedtls")))
    testImplementation("org.junit.jupiter:junit-jupiter-api:5.10.0")
    testRuntimeOnly("org.junit.jupiter:junit-jupiter-engine:5.10.0")
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

configure<KtlintExtension> {
    disabledRules.set(setOf("trailing-comma-on-call-site", "trailing-comma-on-declaration-site"))
}
