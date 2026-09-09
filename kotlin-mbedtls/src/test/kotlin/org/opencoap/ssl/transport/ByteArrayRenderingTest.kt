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

package org.opencoap.ssl.transport

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.opencoap.ssl.PskAuth
import org.opencoap.ssl.util.decodeHex
import java.time.Instant

class ByteArrayRenderingTest {

    @Test
    fun `should render DtlsSessionContext cid as hex`() {
        val ctx = DtlsSessionContext(
            authenticationContext = mapOf("auth" to "dupa"),
            cid = "0102ab".decodeHex(),
            sessionStartTimestamp = Instant.ofEpochSecond(123456789)
        )

        assertEquals(
            "DtlsSessionContext(authenticationContext={auth=dupa}, peerCertificateSubject=null, " +
                "cid=0102ab, sessionStartTimestamp=1973-11-29T21:33:09Z, sessionSuspensionHint=false)",
            ctx.toString()
        )
    }

    @Test
    fun `should render missing DtlsSessionContext cid`() {
        assertTrue(DtlsSessionContext.EMPTY.toString().contains("cid=null"))
    }

    @Test
    fun `should render SessionWithContext blob size and compare by content`() {
        val session = SessionWithContext("0102ab".decodeHex(), mapOf(), Instant.ofEpochSecond(123456789))
        val same = SessionWithContext("0102ab".decodeHex(), mapOf(), Instant.ofEpochSecond(123456789))
        val other = SessionWithContext("0102ac".decodeHex(), mapOf(), Instant.ofEpochSecond(123456789))

        assertEquals(
            "SessionWithContext(sessionBlob=3 bytes, authenticationContext={}, sessionStartTimestamp=1973-11-29T21:33:09Z)",
            session.toString()
        )
        assertEquals(same, session)
        assertEquals(same.hashCode(), session.hashCode())
        assertFalse(other == session)
    }

    @Test
    fun `should redact PskAuth secret and compare by content`() {
        val auth = PskAuth("device-007", byteArrayOf(0x01, 0x02))
        val same = PskAuth("device-007", byteArrayOf(0x01, 0x02))
        val otherSecret = PskAuth("device-007", byteArrayOf(0x01, 0x03))

        assertEquals("PskAuth(pskId=6465766963652d303037, pskSecret=<redacted>)", auth.toString())
        assertEquals(same, auth)
        assertEquals(same.hashCode(), auth.hashCode())
        assertFalse(otherSecret == auth)
    }
}
