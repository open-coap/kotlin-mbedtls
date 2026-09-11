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
import java.nio.ByteOrder

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
 * Also recognises a ClientHello and the `connection_id` extension inside it.
 *
 * Every read is bound-checked: too short a datagram yields null or false, never a throw.
 * The caller's buffer is never modified.
 */
object DtlsParser {
    // Content type `tls12_cid`(0x19) followed by the DTLS 1.2 version (0xFEFD).
    private const val CID_RECORD_PREFIX = 0x19fefd

    private const val EPOCH_OFFSET = 3
    private const val EPOCH_SIZE = 2
    private const val SEQUENCE_NUMBER_OFFSET = 5
    private const val SEQUENCE_NUMBER_SIZE = 6
    private const val CID_OFFSET = 11

    /** Connection id of a `tls12_cid` record, or null when there are not [cidSize] bytes of it. */
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
     * Record epoch, or null when the buffer is too short.
     *
     * Same offset in every DTLS record, so the content type is not checked -- pair with [readCid].
     */
    fun readEpoch(buf: ByteBuffer): Int? {
        if (buf.remaining() < EPOCH_OFFSET + EPOCH_SIZE) {
            return null
        }

        return buf.getShort(buf.position() + EPOCH_OFFSET).toInt() and 0xffff
    }

    /** 48-bit record sequence number, or null when the buffer is too short. See [readEpoch]. */
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

    /** Why a datagram is not a DTLS ClientHello, or [VALID] when it is. */
    enum class ClientHelloCheck { VALID, TOO_SHORT, BAD_HEADER, BAD_HANDSHAKE_TYPE }

    fun checkClientHello(buf: ByteBuffer): ClientHelloCheck {
        // The fixed-offset reads require 14 bytes; a valid ClientHello requires at least 67.
        if (buf.remaining() < CLIENT_HELLO_HEADER_SIZE) {
            return ClientHelloCheck.TOO_SHORT
        }

        val workingBuf = buf.slice().order(ByteOrder.BIG_ENDIAN)

        // Check if the header is correct:
        // - Content Type is Handshake(0x16),
        // - Major version is 1 (0xFE),
        // - Minor version is any,
        // - Epoch is 0
        val header = (workingBuf.getLong(0) or 0x0000FF0000000000) ushr 24
        if (header != 0x16FEFF0000L) {
            return ClientHelloCheck.BAD_HEADER
        }

        // Check if it is a ClientHello handshake
        val handshakeType = workingBuf.get(HANDSHAKE_TYPE_OFFSET).toInt()
        if (handshakeType != HANDSHAKE_TYPE_CLIENT_HELLO) {
            return ClientHelloCheck.BAD_HANDSHAKE_TYPE
        }

        return ClientHelloCheck.VALID
    }

    /**
     * Walks a ClientHello looking for the `connection_id` extension.
     *
     * Lengths here are attacker-controlled, so every step is bound-checked. Expects a buffer
     * positioned at the start of the record, as [checkClientHello] accepted.
     */
    fun supportsCidExtension(buf: ByteBuffer): Boolean {
        val workingBuffer = buf.slice().order(ByteOrder.BIG_ENDIAN)

        // Go to the start of extensions
        // Skip DTLSHeader(13) + HandshakeHeader(12) + SessionIDLengthOffset(34)
        if (!workingBuffer.trySeek(59)) return false
        // Skip variable-length Session ID
        if (!workingBuffer.trySkipByteLengthPrefixed()) return false
        // Skip variable-length Cookie
        if (!workingBuffer.trySkipByteLengthPrefixed()) return false
        // Skip variable-length CipherSuites
        if (!workingBuffer.trySkipShortLengthPrefixed()) return false
        // Skip variable-length CompressionMethods
        if (!workingBuffer.trySkipByteLengthPrefixed()) return false
        // Limit buffer to the length of the Extensions block
        if (!workingBuffer.tryLimitShortLengthPrefixed()) return false

        // Search for CID extension
        while (workingBuffer.remaining() >= 4) {
            val type = workingBuffer.getShort()
            if (type == CID_EXTENSION_TYPE) {
                return true
            }

            // Skip to the next extension
            if (!workingBuffer.trySkipShortLengthPrefixed()) return false
        }

        return false
    }

    private const val CLIENT_HELLO_HEADER_SIZE = 14
    private const val HANDSHAKE_TYPE_OFFSET = 13
    private const val HANDSHAKE_TYPE_CLIENT_HELLO = 1
    private val CID_EXTENSION_TYPE = 0x36.toShort()
}

// Bound-checked seeks. Each returns false, buffer untouched, when the field does not fit.
private fun ByteBuffer.trySeek(offset: Int): Boolean {
    if (remaining() < offset) return false
    position(position() + offset)
    return true
}

private fun ByteBuffer.trySkipByteLengthPrefixed(): Boolean {
    if (remaining() < Byte.SIZE_BYTES) return false
    val length = get(position()).toUByte().toInt()
    return trySeek(Byte.SIZE_BYTES + length)
}

private fun ByteBuffer.trySkipShortLengthPrefixed(): Boolean {
    if (remaining() < Short.SIZE_BYTES) return false
    val length = getShort(position()).toUShort().toInt()
    return trySeek(Short.SIZE_BYTES + length)
}

private fun ByteBuffer.tryLimitShortLengthPrefixed(): Boolean {
    if (remaining() < Short.SIZE_BYTES) return false
    val length = getShort(position()).toUShort().toInt()
    if (remaining() - Short.SIZE_BYTES < length) return false
    position(position() + Short.SIZE_BYTES)
    limit(position() + length)
    return true
}
