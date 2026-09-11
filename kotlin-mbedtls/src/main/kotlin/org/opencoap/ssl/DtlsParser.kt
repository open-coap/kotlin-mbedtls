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

import java.nio.ByteBuffer

/**
 * Reads fields of a DTLS 1.2 record header without consuming the record.
 *
 * Offsets are relative to the buffer's current position:
 * ```
 * 0      content type (0x19 tls12_cid, 0x16 handshake, 0x17 application data)
 * 1..2   protocol version (0xFEFD for DTLS 1.2)
 * 3..4   epoch (uint16)
 * 5..10  sequence number (uint48)
 * 11..   connection id, `tls12_cid` records only
 * ```
 *
 * Every read is bound-checked and yields null for a datagram too short to hold the field, so a
 * truncated or malformed datagram is filtered rather than thrown out of the receive path. All
 * reads are absolute, leaving the buffer's position undisturbed.
 */
object DtlsParser {
    // Content type `tls12_cid`(0x19) followed by the DTLS 1.2 version (0xFEFD).
    private const val CID_RECORD_PREFIX = 0x19fefd

    private const val EPOCH_OFFSET = 3
    private const val EPOCH_SIZE = 2
    private const val SEQUENCE_NUMBER_OFFSET = 5
    private const val SEQUENCE_NUMBER_SIZE = 6
    private const val CID_OFFSET = 11

    /**
     * Reads the connection id of a `tls12_cid` record, or null when the buffer does not hold a
     * DTLS 1.2 CID record carrying at least [cidSize] connection id bytes.
     */
    fun readCid(cidSize: Int, buf: ByteBuffer): ByteArray? {
        val pos = buf.position()
        if (buf.remaining() < CID_OFFSET + cidSize) {
            // too short
            return null
        }
        if ((buf.getInt(pos) shr 8) != CID_RECORD_PREFIX) {
            // not a dtls+cid packet
            return null
        }

        val cid = ByteArray(cidSize)
        for (i in 0 until cidSize) {
            cid[i] = buf.get(pos + CID_OFFSET + i)
        }
        return cid
    }

    /**
     * Reads the record epoch, or null when the buffer is too short to hold it.
     *
     * The epoch sits at the same offset in every DTLS record, so the content type is not
     * checked here; callers that need a CID record should pair this with [readCid].
     */
    fun readEpoch(buf: ByteBuffer): Int? {
        if (buf.remaining() < EPOCH_OFFSET + EPOCH_SIZE) {
            return null
        }

        return buf.getShort(buf.position() + EPOCH_OFFSET).toInt() and 0xffff
    }

    /**
     * Reads the 48-bit record sequence number, or null when the buffer is too short to hold it.
     *
     * As with [readEpoch], the content type is not checked.
     */
    fun readSequenceNumber(buf: ByteBuffer): Long? {
        if (buf.remaining() < SEQUENCE_NUMBER_OFFSET + SEQUENCE_NUMBER_SIZE) {
            return null
        }

        val pos = buf.position() + SEQUENCE_NUMBER_OFFSET
        var sequenceNumber = 0L
        for (i in 0 until SEQUENCE_NUMBER_SIZE) {
            sequenceNumber = (sequenceNumber shl 8) or (buf.get(pos + i).toLong() and 0xff)
        }
        return sequenceNumber
    }
}
