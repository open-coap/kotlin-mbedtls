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

data class MbedtlsVersion(val major: Int, val minor: Int, val patch: Int) {
    override fun toString(): String = "$major.$minor.$patch"
}

/**
 * mbedtls starts a stored session (`mbedtls_ssl_context_save`) with the version of mbedtls that wrote it, and
 * `mbedtls_ssl_context_load` refuses any other version, even when the format did not change.
 * This upgrades sessions stored by the previous mbedtls version, so they survive an mbedtls upgrade.
 */
object StoredSessionVersion {
    private const val VERSION_LEN = 3

    @JvmStatic
    val current: MbedtlsVersion = MbedtlsApi.mbedtls_version_get_number().let {
        MbedtlsVersion(it ushr 24 and 0xFF, it ushr 16 and 0xFF, it ushr 8 and 0xFF)
    }

    // Serialisation format of 4.1.0 and 4.2.0 is identical, only the version in the header differs.
    // On each mbedtls upgrade, verify the format against the previous version and update both.
    private val previous = MbedtlsVersion(4, 1, 0)
    private val upgradableTo = MbedtlsVersion(4, 2, 0)

    /**
     * Version of mbedtls that stored the session, or null when the session is too short.
     */
    @JvmStatic
    fun of(session: ByteArray): MbedtlsVersion? {
        if (session.size < VERSION_LEN) return null
        return MbedtlsVersion(session[0].toUByte().toInt(), session[1].toUByte().toInt(), session[2].toUByte().toInt())
    }

    /**
     * Upgrades the session in place, so the running mbedtls can load it. Leaves it unchanged when it can't be upgraded.
     */
    @JvmStatic
    fun upgrade(session: ByteArray): ByteArray {
        if (current != upgradableTo || of(session) != previous) return session

        session[0] = current.major.toByte()
        session[1] = current.minor.toByte()
        session[2] = current.patch.toByte()
        return session
    }
}
