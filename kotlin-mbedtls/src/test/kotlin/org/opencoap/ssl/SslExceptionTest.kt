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

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test

class SslExceptionTest {

    @Test
    fun `should translate error code`() {
        val sslException = SslException.from(-10240)

        assertEquals("X509 - Input invalid [-0x2800]", sslException.message)
    }

    @Test
    fun `should name PSA aliased ssl error codes`() {
        // mbedTLS 4.x moved these three onto PSA statuses, where mbedtls_strerror used to render
        // e.g. "UNKNOWN ERROR CODE (0080) : HMAC_DRBG - Read/write error in file" for -135
        assertEquals(
            "MBEDTLS_ERR_SSL_BAD_INPUT_DATA / PSA_ERROR_INVALID_ARGUMENT [-0x0087]",
            SslException.from(MbedtlsApi.MBEDTLS_ERR_SSL_BAD_INPUT_DATA).message
        )
        assertEquals(
            "MBEDTLS_ERR_SSL_BUFFER_TOO_SMALL / PSA_ERROR_BUFFER_TOO_SMALL [-0x008A]",
            SslException.from(MbedtlsApi.MBEDTLS_ERR_SSL_BUFFER_TOO_SMALL).message
        )
        assertEquals(
            "MBEDTLS_ERR_SSL_ALLOC_FAILED / PSA_ERROR_INSUFFICIENT_MEMORY [-0x008D]",
            SslException.from(MbedtlsApi.MBEDTLS_ERR_SSL_ALLOC_FAILED).message
        )
    }

    @Test
    fun `should name plain PSA status codes`() {
        assertEquals("PSA_ERROR_INVALID_SIGNATURE [-0x0095]", SslException.from(MbedtlsApi.PSA_ERROR_INVALID_SIGNATURE).message)

        // both ends of the range
        assertEquals("PSA_ERROR_GENERIC_ERROR [-0x0084]", SslException.from(MbedtlsApi.PSA_ERROR_GENERIC_ERROR).message)
        assertEquals("PSA_ERROR_DATA_INVALID [-0x0099]", SslException.from(MbedtlsApi.PSA_ERROR_DATA_INVALID).message)
    }

    @Test
    fun `should keep resolving non PSA error codes through mbedtls_strerror`() {
        assertEquals("SSL - DTLS client must retry for hello verification [-0x6A80]", SslException.from(-0x6A80).message)
        assertEquals("SSL - Processing of the Certificate handshake message failed [-0x7A00]", SslException.from(-0x7A00).message)

        // just below the PSA range, still a genuine mbedTLS low-level code
        assertEquals("NET - Reading information from the socket failed", SslException.translateError(MbedtlsApi.MBEDTLS_ERR_NET_RECV_FAILED))
    }

    @Test
    fun `should return CloseNotifyException for peer close notify`() {
        assertEquals(CloseNotifyException, SslException.from(MbedtlsApi.MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY))
    }
}
