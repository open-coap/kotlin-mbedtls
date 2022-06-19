/*
 * Copyright (c) 2022 kotlin-mbedtls contributors (https://github.com/open-coap/kotlin-mbedtls)
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

import com.sun.jna.Memory

open class SslException(message: String) : Exception(message) {

    companion object {
        fun from(error: Int): SslException {
            if (error == MbedtlsApi.MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY) {
                return CloseNotifyException
            }
            return SslException(translateError(error) + " [" + error + "]")
        }

        internal fun translateError(error: Int): String {
            val buffer = Memory(100)
            MbedtlsApi.mbedtls_strerror(error, buffer, buffer.size().toInt())
            return buffer.getString(0).trim()
        }
    }
}

object HelloVerifyRequired : SslException(translateError(MbedtlsApi.MBEDTLS_ERR_SSL_HELLO_VERIFY_REQUIRED))
object CloseNotifyException : SslException(translateError(MbedtlsApi.MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY))
