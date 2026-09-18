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

import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNotEquals
import org.junit.jupiter.api.Assertions.assertSame
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.opencoap.ssl.transport.EncryptionContext.Version
import org.opencoap.ssl.util.StoredSessionPair
import java.security.SecureRandom

class DtlsSessionEncryptionEngineTest {
    private val key1 = ByteArray(16).also(SecureRandom()::nextBytes)
    private val key2 = ByteArray(32).also(SecureRandom()::nextBytes)
    private val keyStore = mapOf("key1" to key1, "key2" to key2)

    private fun aesEngine(activeKeyId: String = "key1") = DtlsSessionEncryptionEngine(
        DtlsSessionEncryptionConfig(Version.AES_GCM, keyStore, activeKeyId)
    )

    @Test
    fun `should seal and open a session blob`() {
        val engine = aesEngine()
        val blob = StoredSessionPair.srvSession

        val (sealed, ctx) = engine.activeEncryptionStrategy().encrypt(blob)

        assertEquals(Version.AES_GCM, ctx.version)
        assertEquals("key1", ctx[EncryptionContext.KEY_ID_PROP])
        assertTrue(ctx[EncryptionContext.IV_PROP] != null, "nonce must be recorded in the context")
        assertFalse(sealed.contentEquals(blob), "blob must not be stored in the clear")
        assertArrayEquals(blob, engine.encryptionStrategy(ctx).decrypt(sealed))
    }

    @Test
    fun `should reject a sealed blob whose every single bit was flipped in turn`() {
        val engine = aesEngine()
        val (sealed, ctx) = engine.activeEncryptionStrategy().encrypt(StoredSessionPair.srvSession)

        // the bare mbedTLS blob accepted a third of these; the tag must catch all of them
        var rejected = 0
        for (byteIdx in sealed.indices) {
            for (bitIdx in 0 until 8) {
                val tampered = sealed.copyOf()
                tampered[byteIdx] = (tampered[byteIdx].toInt() xor (1 shl bitIdx)).toByte()
                assertThrows(DtlsSessionEncryptionException::class.java) {
                    engine.encryptionStrategy(ctx).decrypt(tampered)
                }
                rejected++
            }
        }
        assertEquals(sealed.size * 8, rejected)
    }

    @Test
    fun `should reject a sealed blob opened with a tampered nonce`() {
        val engine = aesEngine()
        val (sealed, ctx) = engine.activeEncryptionStrategy().encrypt(StoredSessionPair.srvSession)
        val nonce = ctx[EncryptionContext.IV_PROP]!!.toCharArray().also { it[0] = if (it[0] == 'A') 'B' else 'A' }

        val tamperedCtx = EncryptionContext(Version.AES_GCM, ctx.properties + (EncryptionContext.IV_PROP to String(nonce)))

        assertThrows(DtlsSessionEncryptionException::class.java) {
            engine.encryptionStrategy(tamperedCtx).decrypt(sealed)
        }
    }

    @Test
    fun `should reject a sealed blob opened under the wrong key`() {
        val (sealed, ctx) = aesEngine("key1").activeEncryptionStrategy().encrypt(StoredSessionPair.srvSession)
        val underKey2 = EncryptionContext(Version.AES_GCM, ctx.properties + (EncryptionContext.KEY_ID_PROP to "key2"))

        assertThrows(DtlsSessionEncryptionException::class.java) {
            aesEngine().encryptionStrategy(underKey2).decrypt(sealed)
        }
    }

    @Test
    fun `should open a blob sealed under a rotated-out key`() {
        val (sealed, ctx) = aesEngine("key1").activeEncryptionStrategy().encrypt(StoredSessionPair.srvSession)

        val afterRotation = aesEngine("key2")
        assertEquals("key2", afterRotation.activeEncryptionStrategy().encrypt("x".encodeToByteArray()).second[EncryptionContext.KEY_ID_PROP])
        assertArrayEquals(StoredSessionPair.srvSession, afterRotation.encryptionStrategy(ctx).decrypt(sealed))
    }

    @Test
    fun `should use a fresh nonce for every seal`() {
        val strategy = aesEngine().activeEncryptionStrategy()
        val blob = StoredSessionPair.srvSession

        val nonces = (1..64).map { strategy.encrypt(blob).second[EncryptionContext.IV_PROP] }

        assertEquals(64, nonces.toSet().size, "nonce reuse under one key breaks GCM")
        assertEquals(64, (1..64).map { strategy.encrypt(blob).first.toList() }.toSet().size)
    }

    @Test
    fun `should pass the blob through when no encryption is configured`() {
        val data = "test".encodeToByteArray()

        assertSame(data, aesEngine().encryptionStrategy(null).decrypt(data))
        assertSame(data, aesEngine().encryptionStrategy(EncryptionContext(Version.NO_ENCRYPTION)).decrypt(data))

        val noEncEngine = DtlsSessionEncryptionEngine(DtlsSessionEncryptionConfig(Version.NO_ENCRYPTION))
        val (sealed, ctx) = noEncEngine.activeEncryptionStrategy().encrypt(data)
        assertSame(data, sealed)
        assertEquals(Version.NO_ENCRYPTION, ctx.version)
    }

    @Test
    fun `should read a version and properties that came from a store`() {
        assertEquals(EncryptionContext(Version.AES_GCM, mapOf("keyId" to "key1")), EncryptionContext("AES_GCM", mapOf("keyId" to "key1")))
        assertEquals(EncryptionContext(Version.NO_ENCRYPTION), EncryptionContext(null, null))
    }

    @Test
    fun `should fail when the key is not available`() {
        val ctx = EncryptionContext(Version.AES_GCM, mapOf(EncryptionContext.KEY_ID_PROP to "missing"))
        assertThrows(DtlsSessionEncryptionException::class.java) { aesEngine().encryptionStrategy(ctx) }

        val noKeyId = EncryptionContext(Version.AES_GCM, mapOf())
        assertThrows(DtlsSessionEncryptionException::class.java) { aesEngine().encryptionStrategy(noKeyId) }
    }

    @Test
    fun `should fail when the nonce is missing from the context`() {
        val (sealed, ctx) = aesEngine().activeEncryptionStrategy().encrypt(StoredSessionPair.srvSession)
        val withoutNonce = EncryptionContext(Version.AES_GCM, ctx.properties - EncryptionContext.IV_PROP)

        assertThrows(DtlsSessionEncryptionException::class.java) {
            aesEngine().encryptionStrategy(withoutNonce).decrypt(sealed)
        }
    }

    @Test
    fun `should require an active key id when AES_GCM seals new sessions`() {
        assertThrows(IllegalArgumentException::class.java) {
            DtlsSessionEncryptionConfig(Version.AES_GCM, keyStore)
        }
    }

    @Test
    fun `should not leak the blob into the ciphertext length pattern`() {
        val (sealed, _) = aesEngine().activeEncryptionStrategy().encrypt(StoredSessionPair.srvSession)

        assertEquals(StoredSessionPair.srvSession.size + AesEncryptionStrategy.GCM_TAG_LENGTH_BITS / 8, sealed.size)
        assertNotEquals(StoredSessionPair.srvSession.first(), sealed.first())
    }
}
