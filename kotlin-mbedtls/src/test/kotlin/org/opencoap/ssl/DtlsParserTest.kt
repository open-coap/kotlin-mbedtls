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

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Test
import org.opencoap.ssl.transport.asByteBuffer
import org.opencoap.ssl.transport.toHex
import org.opencoap.ssl.util.decodeHex
import java.nio.ByteBuffer
import kotlin.random.Random

class DtlsParserTest {
    // A `tls12_cid` record: 0x19 FEFD, epoch 0x0001, sequence number 0x000000000001,
    // followed by a 16 byte connection id.
    private val cidRecord =
        "19fefd0001000000000001db04684e33424e42801f0e38023d243800280001000000000001a7eddd3aa34f5164499ca1fcaede85f9e77036ad66c2affb2ae9c97c5a78adb9"

    @Test
    fun `should peek CID from DTLS Packet`() {
        val dtlsPacket = cidRecord.decodeHex().asByteBuffer()

        val cid = DtlsParser.readCid(16, dtlsPacket)

        assertEquals("db04684e33424e42801f0e38023d2438", cid?.toHex())
        assertEquals(0, dtlsPacket.position())
    }

    @Test
    fun `should peek CID from DTLS Packet with different sizes`() {
        assertEquals(
            "db",
            DtlsParser.readCid(1, "19fefd0301000000000003db04684e3342".decodeHex().asByteBuffer())?.toHex()
        )
        assertEquals(
            "db04684e",
            DtlsParser.readCid(4, "19fefdf001000000000001db04684e3342".decodeHex().asByteBuffer())?.toHex()
        )
    }

    @Test
    fun `should return null when not DTLS Packet`() {
        assertNull(DtlsParser.readCid(4, "17fefd0001000000000001db04684e3342".decodeHex().asByteBuffer()))
        assertNull(DtlsParser.readCid(4, "19f0fd0001000000000001db04684e3342".decodeHex().asByteBuffer()))
        assertNull(DtlsParser.readCid(4, "19fef00001000000000001db04684e3342".decodeHex().asByteBuffer()))
    }

    @Test
    fun `should return null when too short DTLS Packet`() {
        assertNull(
            DtlsParser.readCid(7, "19fefdf001000000000001db04684e3342".decodeHex().asByteBuffer())?.toHex()
        )
        assertNull(
            DtlsParser.readCid(2, "19fefd".decodeHex().asByteBuffer())?.toHex()
        )
    }

    @Test
    fun `should read epoch`() {
        assertEquals(1, DtlsParser.readEpoch(cidRecord.decodeHex().asByteBuffer()))
        assertEquals(0x0301, DtlsParser.readEpoch("19fefd0301000000000003db".decodeHex().asByteBuffer()))
        // the top bit of the epoch must not sign-extend
        assertEquals(0xf001, DtlsParser.readEpoch("19fefdf001000000000001db".decodeHex().asByteBuffer()))
        assertEquals(0xffff, DtlsParser.readEpoch("19fefdffff000000000001db".decodeHex().asByteBuffer()))
    }

    @Test
    fun `should read epoch of a handshake record`() {
        // the epoch offset is the same for every content type, so no CID record is required
        assertEquals(0, DtlsParser.readEpoch("16fefd0000000000000000000000".decodeHex().asByteBuffer()))
    }

    @Test
    fun `should read sequence number`() {
        assertEquals(1, DtlsParser.readSequenceNumber(cidRecord.decodeHex().asByteBuffer()))
        assertEquals(3, DtlsParser.readSequenceNumber("19fefd0301000000000003db".decodeHex().asByteBuffer()))
        assertEquals(
            0x0102030405L,
            DtlsParser.readSequenceNumber("19fefd00010001020304050000".decodeHex().asByteBuffer())
        )
        // the whole 48 bit range is readable, and no byte sign-extends
        assertEquals(
            0xffffffffffffL,
            DtlsParser.readSequenceNumber("19fefd0001ffffffffffff0000".decodeHex().asByteBuffer())
        )
    }

    @Test
    fun `should not read epoch and sequence number beyond the datagram`() {
        val record = cidRecord.decodeHex()

        // epoch needs 5 bytes, sequence number needs 11
        for (len in 0..4) {
            assertNull(DtlsParser.readEpoch(record.copyOf(len).asByteBuffer()), "epoch at length $len")
        }
        for (len in 0..10) {
            assertNull(DtlsParser.readSequenceNumber(record.copyOf(len).asByteBuffer()), "sequence number at length $len")
        }

        assertEquals(1, DtlsParser.readEpoch(record.copyOf(5).asByteBuffer()))
        assertEquals(1, DtlsParser.readSequenceNumber(record.copyOf(11).asByteBuffer()))
    }

    @Test
    fun `should read relative to buffer position and leave it undisturbed`() {
        // the record is prefixed with junk, so absolute-from-zero reads would return wrong values
        val buf = ("ffffff" + cidRecord).decodeHex().asByteBuffer()
        buf.position(3)

        assertEquals("db04684e33424e42801f0e38023d2438", DtlsParser.readCid(16, buf)?.toHex())
        assertEquals(1, DtlsParser.readEpoch(buf))
        assertEquals(1, DtlsParser.readSequenceNumber(buf))
        assertEquals(3, buf.position())
    }

    @Test
    fun `should respect buffer limit, not capacity`() {
        val buf = cidRecord.decodeHex().asByteBuffer()
        buf.limit(10)

        assertNull(DtlsParser.readCid(16, buf))
        assertNull(DtlsParser.readSequenceNumber(buf))
        assertEquals(1, DtlsParser.readEpoch(buf))
        assertEquals(0, buf.position())
    }

    @Test
    fun `should not throw for randomised datagrams`() {
        val random = Random(1)

        repeat(20_000) {
            val buf = random.nextBytes(random.nextInt(0, 32)).asByteBuffer()

            DtlsParser.readCid(16, buf)
            DtlsParser.readEpoch(buf)
            DtlsParser.readSequenceNumber(buf)
            assertEquals(0, buf.position())
        }
    }

    @Test
    fun `should read from a direct buffer`() {
        val bytes = cidRecord.decodeHex()
        val buf = ByteBuffer.allocateDirect(bytes.size)
        buf.put(bytes)
        buf.flip()

        assertEquals("db04684e33424e42801f0e38023d2438", DtlsParser.readCid(16, buf)?.toHex())
        assertEquals(1, DtlsParser.readEpoch(buf))
        assertEquals(1, DtlsParser.readSequenceNumber(buf))
        assertEquals(0, buf.position())
    }
}
