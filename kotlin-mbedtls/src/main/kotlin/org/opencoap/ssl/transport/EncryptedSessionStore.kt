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

import java.nio.ByteBuffer
import java.util.concurrent.CompletableFuture

/**
 * Wraps any [SessionStore] so the blob it persists is sealed, giving the store the confidentiality
 * and integrity its contract requires without it knowing anything about encryption:
 *
 * ```
 * val store = EncryptedSessionStore(RedisSessionStore(...), DtlsSessionEncryptionEngine(config))
 * ```
 *
 * The [EncryptionContext] is packed into the blob itself, so no extra columns are needed. A store
 * that wants the context in its own fields — as coap-connector's DynamoDB store does — should call
 * [DtlsSessionEncryptionEngine] directly instead; the two formats are not interchangeable.
 *
 * With [acceptUnsealed] a read falls back to returning an unrecognised blob as-is, which is how a
 * store already holding unsealed blobs is migrated. It is off by default because it lets anyone who
 * can write to the store strip the envelope and bypass the tag check; turn it off once migrated.
 */
class EncryptedSessionStore(
    private val delegate: SessionStore,
    private val engine: DtlsSessionEncryptionEngine,
    private val acceptUnsealed: Boolean = false
) : SessionStore {

    override fun read(cid: CID): CompletableFuture<SessionWithContext?> = delegate.read(cid).thenApply { stored ->
        stored?.copy(sessionBlob = open(stored.sessionBlob))
    }

    override fun write(cid: CID, session: SessionWithContext) = delegate.write(cid, session.copy(sessionBlob = seal(session.sessionBlob)))

    private fun seal(blob: ByteArray): ByteArray {
        val (ciphertext, ctx) = engine.activeEncryptionStrategy().encrypt(blob)
        val version = ctx.version.name.encodeToByteArray()
        val props = ctx.properties.map { (k, v) -> k.encodeToByteArray() to v.encodeToByteArray() }
        require(version.size <= MAX_BYTE && props.size <= MAX_BYTE && props.all { it.first.size <= MAX_BYTE }) {
            "Encryption context does not fit the envelope header"
        }

        val header = MAGIC.size + FIXED_FIELDS + version.size + props.sumOf { 1 + it.first.size + 2 + it.second.size }
        return ByteBuffer.allocate(header + ciphertext.size).apply {
            put(MAGIC)
            put(FORMAT_VERSION)
            put(version.size.toByte()).put(version)
            put(props.size.toByte())
            props.forEach { (k, v) ->
                put(k.size.toByte()).put(k)
                putShort(v.size.toShort()).put(v)
            }
            put(ciphertext)
        }.array()
    }

    private fun open(stored: ByteArray): ByteArray {
        if (!stored.startsWithMagic()) {
            if (acceptUnsealed) return stored
            throw DtlsSessionEncryptionException("Stored session is not sealed")
        }

        val (ctx, ciphertext) = parse(ByteBuffer.wrap(stored).position(MAGIC.size))
        return engine.encryptionStrategy(ctx).decrypt(ciphertext)
    }

    // the header is attacker-influenced, so every parse failure becomes the same rejection
    private fun parse(buf: ByteBuffer): Pair<EncryptionContext, ByteArray> = try {
        val format = buf.get()
        require(format == FORMAT_VERSION) { "Unsupported envelope format $format" }

        val version = buf.getBytes(buf.getUByte()).decodeToString()
        val props = (1..buf.getUByte()).associate {
            buf.getBytes(buf.getUByte()).decodeToString() to buf.getBytes(buf.getShort().toUShort().toInt()).decodeToString()
        }
        EncryptionContext(version, props) to buf.getBytes(buf.remaining())
    } catch (e: RuntimeException) {
        throw DtlsSessionEncryptionException("Malformed envelope header", e)
    }

    private fun ByteArray.startsWithMagic(): Boolean = size >= MAGIC.size && MAGIC.indices.all { this[it] == MAGIC[it] }
    private fun ByteBuffer.getUByte(): Int = get().toUByte().toInt()
    private fun ByteBuffer.getBytes(len: Int): ByteArray = ByteArray(len).also(::get)

    companion object {
        // no mbedTLS context save starts with these, so an unsealed blob is recognisable
        private val MAGIC = byteArrayOf(0xD7.toByte(), 0x15)
        private const val FORMAT_VERSION: Byte = 1
        private const val MAX_BYTE = 255
        private const val FIXED_FIELDS = 3 // format, version length, property count
    }
}
