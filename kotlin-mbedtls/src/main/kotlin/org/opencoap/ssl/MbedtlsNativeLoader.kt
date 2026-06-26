/*
 * Copyright (c) 2022-2026 kotlin-mbedtls contributors (https://github.com/open-coap/kotlin-mbedtls)
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

package org.opencoap.ssl

import java.lang.foreign.Arena
import java.lang.foreign.SymbolLookup
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.StandardCopyOption

/*
Loads the bundled mbedtls native libraries using the Foreign Function & Memory API.

The three platform libraries are extracted from `mbedtls-lib` resources into a single temp directory and
loaded by absolute path, in dependency order (tfpsacrypto -> mbedx509 -> mbedtls), into a long-lived global
Arena. Loading dependencies first lets the dynamic linker satisfy inter-library symbols via SONAME matching,
so RTLD_GLOBAL is not required.
 */
internal object MbedtlsNativeLoader {

    // Dependencies must be loaded before the libraries that need them.
    private val LIB_NAMES = listOf("tfpsacrypto", "mbedx509", "mbedtls")

    // Combined lookup across all three libraries.
    val lookup: SymbolLookup by lazy { load() }

    private fun load(): SymbolLookup {
        val arena = Arena.global()
        val platform = Platform.current()
        val tempDir = Files.createTempDirectory("kotlin-mbedtls").also { it.toFile().deleteOnExit() }

        var combined: SymbolLookup? = null
        for (name in LIB_NAMES) {
            val libFile = extract(platform, name, tempDir)
            val libLookup = SymbolLookup.libraryLookup(libFile, arena)
            combined = combined?.or(libLookup) ?: libLookup
        }
        return combined ?: error("No mbedtls native libraries were loaded")
    }

    private fun extract(platform: Platform, name: String, tempDir: Path): Path {
        val fileName = "${platform.prefix}$name${platform.suffix}"
        val resourcePath = "/${platform.resourceDir}/$fileName"
        val target = tempDir.resolve(fileName)

        val input = javaClass.getResourceAsStream(resourcePath)
            ?: throw UnsatisfiedLinkError("Bundled native library not found on classpath: $resourcePath")
        input.use { Files.copy(it, target, StandardCopyOption.REPLACE_EXISTING) }
        target.toFile().deleteOnExit()
        return target
    }

    private data class Platform(val resourceDir: String, val prefix: String, val suffix: String) {
        companion object {
            fun current(): Platform {
                val os = System.getProperty("os.name").lowercase()
                val arch = System.getProperty("os.arch").lowercase()
                return when {
                    os.contains("mac") || os.contains("darwin") -> Platform("darwin", "lib", ".dylib")
                    os.contains("win") -> Platform("win32-x86-64", "lib", ".dll")
                    os.contains("nux") || os.contains("nix") -> {
                        val isArm = arch.contains("aarch64") || arch.contains("arm64")
                        Platform(if (isArm) "linux-aarch64" else "linux-x86-64", "lib", ".so")
                    }

                    else -> throw UnsatisfiedLinkError("Unsupported platform: os=$os arch=$arch")
                }
            }
        }
    }
}
