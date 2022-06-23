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

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Test
import org.opencoap.ssl.transport.toHex
import org.opencoap.ssl.util.asByteBuffer
import org.opencoap.ssl.util.decodeHex

class SslContextTest {

    @Test
    fun `should peek CID from DTLS Packet`() {
        val dtlsPacket =
            "19fefd0001000000000001db04684e33424e42801f0e38023d243800280001000000000001a7eddd3aa34f5164499ca1fcaede85f9e77036ad66c2affb2ae9c97c5a78adb9"
                .decodeHex().asByteBuffer()

        val cid = SslContext.peekCID(16, dtlsPacket)

        assertEquals("db04684e33424e42801f0e38023d2438", cid?.toHex())
        assertEquals(0, dtlsPacket.position())
    }

    @Test
    fun `should peek CID from DTLS Packet with different sizes`() {
        assertEquals(
            "db",
            SslContext.peekCID(1, "19fefd0301000000000003db04684e3342".decodeHex().asByteBuffer())?.toHex()
        )
        assertEquals(
            "db04684e",
            SslContext.peekCID(4, "19fefdf001000000000001db04684e3342".decodeHex().asByteBuffer())?.toHex()
        )
    }

    @Test
    fun `should return null when not DTLS Packet`() {
        assertNull(SslContext.peekCID(4, "17fefd0001000000000001db04684e3342".decodeHex().asByteBuffer()))
        assertNull(SslContext.peekCID(4, "19f0fd0001000000000001db04684e3342".decodeHex().asByteBuffer()))
        assertNull(SslContext.peekCID(4, "19fef00001000000000001db04684e3342".decodeHex().asByteBuffer()))
    }

    @Test
    fun `should return null when too short DTLS Packet`() {
        assertNull(
            SslContext.peekCID(7, "19fefdf001000000000001db04684e3342".decodeHex().asByteBuffer())?.toHex()
        )
        assertNull(
            SslContext.peekCID(2, "19fefd".decodeHex().asByteBuffer())?.toHex()
        )
    }
}
