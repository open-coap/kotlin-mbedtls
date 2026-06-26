/*
 * Copyright (c) 2022-2025 kotlin-mbedtls contributors (https://github.com/open-coap/kotlin-mbedtls)
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

import org.opencoap.ssl.MbedtlsApi.X509.mbedtls_strerror
import java.lang.foreign.Arena
import java.util.Locale

open class SslException(message: String) : Exception(message) {

    companion object {
        fun from(error: Int): SslException = when (error) {
            MbedtlsApi.MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY -> CloseNotifyException
            else -> SslException(String.format(Locale.US, "%s [-0x%04X]", translateError(error), -error))
        }

        internal fun translateError(error: Int): String = Arena.ofConfined().use { arena ->
            val buffer = arena.allocate(BUFFER_SIZE)
            mbedtls_strerror(error, buffer, BUFFER_SIZE.toInt())
            buffer.getString(0).trim()
        }

        private const val BUFFER_SIZE = 100L
    }
}

object HelloVerifyRequired : SslException(translateError(MbedtlsApi.MBEDTLS_ERR_SSL_HELLO_VERIFY_REQUIRED))
object CloseNotifyException : SslException(translateError(MbedtlsApi.MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY))
