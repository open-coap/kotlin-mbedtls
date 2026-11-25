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

/**
 * mbedtls version, encoded as in `mbedtls_version_get_number()`: 0xMMNNPP00, e.g. 0x04020000 for 4.2.0.
 */
typealias MbedtlsVersion = Int

/**
 * Upgrades a session stored by mbedtls [from] to the format of mbedtls [to].
 * Rewriting the version in the header is enough while the serialisation format does not change.
 */
internal class Upgrade(val from: MbedtlsVersion, val to: MbedtlsVersion) {
    fun apply(session: ByteArray): ByteArray {
        session[0] = (to ushr 24).toByte()
        session[1] = (to ushr 16).toByte()
        session[2] = (to ushr 8).toByte()
        return session
    }
}

/**
 * mbedtls starts a stored session (`mbedtls_ssl_context_save`) with the version of mbedtls that wrote it, and
 * `mbedtls_ssl_context_load` refuses any other version, even when the format did not change.
 * This upgrades sessions stored by older mbedtls versions, so they survive an mbedtls upgrade.
 */
object StoredSessionVersion {
    private const val VERSION_LEN = 3

    // One step per mbedtls upgrade, oldest first, the last one ending at the running mbedtls version.
    // On each mbedtls upgrade, verify the serialisation format against the previous version and add a step.
    internal val upgrades = listOf(
        Upgrade(from = 0x04010000, to = 0x04020000), // format identical
    )

    @JvmStatic
    val current: MbedtlsVersion = MbedtlsApi.mbedtls_version_get_number()

    /**
     * Version of mbedtls that stored the session, or null when the session is too short.
     */
    @JvmStatic
    fun of(session: ByteArray): MbedtlsVersion? {
        if (session.size < VERSION_LEN) return null
        return ((session[0].toInt() and 0xFF) shl 24) or ((session[1].toInt() and 0xFF) shl 16) or ((session[2].toInt() and 0xFF) shl 8)
    }

    /**
     * Upgrades the session in place, so the running mbedtls can load it. Leaves it unchanged when it can't be upgraded.
     */
    @JvmStatic
    fun upgrade(session: ByteArray): ByteArray = upgrade(session, upgrades, current)

    internal fun upgrade(session: ByteArray, upgrades: List<Upgrade>, target: MbedtlsVersion): ByteArray {
        val version = of(session) ?: return session
        val start = upgrades.indexOfFirst { it.from == version }
        // all steps or none, so a session is never left half upgraded
        if (start < 0 || upgrades.last().to != target) return session

        return upgrades.subList(start, upgrades.size).fold(session) { s, step -> step.apply(s) }
    }
}
