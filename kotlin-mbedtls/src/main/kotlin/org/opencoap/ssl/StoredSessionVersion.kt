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
 * mbedtls starts a stored session (`mbedtls_ssl_context_save`) with the version of mbedtls that wrote it, and
 * `mbedtls_ssl_context_load` refuses any other version, even when the format did not change.
 * This upgrades sessions stored by the previous mbedtls version, so they survive an mbedtls upgrade.
 *
 * Versions are encoded as in `mbedtls_version_get_number()`: 0xMMNNPP00, e.g. 0x04020000 for 4.2.0.
 */
object StoredSessionVersion {
    private const val VERSION_LEN = 3

    // Serialisation format of 4.1.0 and 4.2.0 is identical, only the version in the header differs.
    // On each mbedtls upgrade, verify the format against the previous version and update both.
    private const val PREVIOUS = 0x04010000
    private const val UPGRADABLE_TO = 0x04020000

    @JvmStatic
    val current: Int = MbedtlsApi.mbedtls_version_get_number()

    /**
     * Version of mbedtls that stored the session, or null when the session is too short.
     */
    @JvmStatic
    fun of(session: ByteArray): Int? {
        if (session.size < VERSION_LEN) return null
        return ((session[0].toInt() and 0xFF) shl 24) or ((session[1].toInt() and 0xFF) shl 16) or ((session[2].toInt() and 0xFF) shl 8)
    }

    /**
     * Upgrades the session in place, so the running mbedtls can load it. Leaves it unchanged when it can't be upgraded.
     */
    @JvmStatic
    fun upgrade(session: ByteArray): ByteArray {
        if (current != UPGRADABLE_TO || of(session) != PREVIOUS) return session

        session[0] = (current ushr 24).toByte()
        session[1] = (current ushr 16).toByte()
        session[2] = (current ushr 8).toByte()
        return session
    }
}
