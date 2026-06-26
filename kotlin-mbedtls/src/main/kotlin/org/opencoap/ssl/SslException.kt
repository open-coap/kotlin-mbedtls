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

import java.util.Locale

open class SslException(message: String) : Exception(message) {

    companion object {
        /**
         * Resolves an mbedtls error code into a human readable message. Registered by the active engine
         * (e.g. JNA's `mbedtls_strerror`); defaults to a bare hex code when no engine is loaded.
         */
        @Volatile
        @JvmStatic
        var errorTranslator: (Int) -> String = { error -> String.format(Locale.US, "-0x%04X", -error) }

        fun from(error: Int): SslException = when (error) {
            Mbedtls.MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY -> CloseNotifyException
            else -> SslException(String.format(Locale.US, "%s [-0x%04X]", translateError(error), -error))
        }

        internal fun translateError(error: Int): String = errorTranslator(error)
    }
}

object HelloVerifyRequired : SslException(translateError(Mbedtls.MBEDTLS_ERR_SSL_HELLO_VERIFY_REQUIRED))
object CloseNotifyException : SslException(translateError(Mbedtls.MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY))

/** Verifies an mbedtls return code, throwing [SslException] on negative values. */
internal fun Int.verify(): Int {
    if (this >= 0) return this
    throw SslException.from(this)
}
