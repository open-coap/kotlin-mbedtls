/*
 * Copyright (c) 2022-2023 kotlin-mbedtls contributors (https://github.com/open-coap/kotlin-mbedtls)
 * SPDX-License-Identifier: Apache-2.0
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import org.jetbrains.kotlin.gradle.tasks.KotlinCompile
import org.jlleitschuh.gradle.ktlint.KtlintExtension

plugins {
    id("org.jetbrains.kotlin.jvm")
    id("org.jlleitschuh.gradle.ktlint") version "11.3.1"
    id("com.adarshr.test-logger") version "3.2.0"
    id("io.gitlab.arturbosch.detekt") version "1.22.0"
    id("me.champeau.jmh") version "0.7.0"
}

dependencies {
    api(project(":kotlin-mbedtls"))

    api(platform("org.jetbrains.kotlin:kotlin-bom"))
    api("org.jetbrains.kotlin:kotlin-stdlib-jdk8")
    api("io.netty:netty-handler:4.1.92.Final")

    // TESTS
    testImplementation(testFixtures(project(":kotlin-mbedtls")))

    testImplementation("org.junit.jupiter:junit-jupiter-api:5.9.2")
    testRuntimeOnly("org.junit.jupiter:junit-jupiter-engine:5.9.2")
    testImplementation("ch.qos.logback:logback-classic:1.3.0")
    testImplementation("org.awaitility:awaitility-kotlin:4.2.0")
    testImplementation("io.netty:netty-all:4.1.92.Final")
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
