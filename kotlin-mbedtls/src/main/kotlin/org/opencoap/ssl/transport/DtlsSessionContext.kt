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

package org.opencoap.ssl.transport

typealias AuthenticationContext = Map<String, String>

data class DtlsSessionContext @JvmOverloads constructor(
    val authenticationContext: AuthenticationContext = emptyMap(),
    val peerCertificateSubject: String? = null,
    val cid: ByteArray? = null
) {
    companion object {
        @JvmField
        val EMPTY = DtlsSessionContext()
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as DtlsSessionContext

        if (authenticationContext != other.authenticationContext) return false
        if (peerCertificateSubject != other.peerCertificateSubject) return false
        if (cid != null) {
            if (other.cid == null) return false
            if (!cid.contentEquals(other.cid)) return false
        } else if (other.cid != null) return false

        return true
    }

    override fun hashCode(): Int {
        var result = authenticationContext.hashCode()
        result = 31 * result + (peerCertificateSubject?.hashCode() ?: 0)
        result = 31 * result + (cid?.contentHashCode() ?: 0)
        return result
    }
}
