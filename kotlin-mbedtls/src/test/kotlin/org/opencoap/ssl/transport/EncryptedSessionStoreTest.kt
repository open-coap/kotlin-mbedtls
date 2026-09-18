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
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Test
import org.opencoap.ssl.transport.EncryptionContext.Version
import org.opencoap.ssl.util.StoredSessionPair
import java.security.SecureRandom
import java.time.Instant
import java.util.concurrent.CompletableFuture
import java.util.concurrent.CompletableFuture.completedFuture
import java.util.concurrent.CompletionException

class EncryptedSessionStoreTest {
    private val cid = byteArrayOf(1, 2, 3, 4)
    private val delegate = CapturingSessionStore()
    private val engine = DtlsSessionEncryptionEngine(
        DtlsSessionEncryptionConfig(Version.AES_GCM, mapOf("k1" to ByteArray(16).also(SecureRandom()::nextBytes)), "k1")
    )
    private val store = EncryptedSessionStore(delegate, engine)

    private fun session(blob: ByteArray = StoredSessionPair.srvSession) = SessionWithContext(blob, mapOf("devId" to "dev-007"), Instant.ofEpochSecond(123456789))

    @Test
    fun `should seal on write and open on read`() {
        store.write(cid, session())

        val stored = delegate.stored()!!
        assertFalse(stored.sessionBlob.contentEquals(StoredSessionPair.srvSession), "delegate must not see the plain blob")

        val read = store.read(cid).join()!!
        assertArrayEquals(StoredSessionPair.srvSession, read.sessionBlob)
        assertEquals(mapOf("devId" to "dev-007"), read.authenticationContext)
        assertEquals(Instant.ofEpochSecond(123456789), read.sessionStartTimestamp)
    }

    @Test
    fun `should reject a sealed blob tampered with in the delegate`() {
        store.write(cid, session())

        for (byteIdx in delegate.stored()!!.sessionBlob.indices) {
            delegate.flipBit(byteIdx)
            assertRejected { store.read(cid).join() }
            delegate.flipBit(byteIdx) // restore
        }
    }

    @Test
    fun `should pass through a missing session`() {
        assertNull(store.read(cid).join())
    }

    @Test
    fun `should reject an unsealed blob by default`() {
        delegate.write(cid, session())

        assertRejected { store.read(cid).join() }
    }

    @Test
    fun `should accept an unsealed blob while migrating`() {
        delegate.write(cid, session())

        val migrating = EncryptedSessionStore(delegate, engine, acceptUnsealed = true)
        assertArrayEquals(StoredSessionPair.srvSession, migrating.read(cid).join()!!.sessionBlob)
    }

    @Test
    fun `should reject a truncated envelope`() {
        store.write(cid, session())
        delegate.truncate()

        assertRejected { store.read(cid).join() }
    }

    @Test
    fun `should round trip when no encryption is configured`() {
        val plainEngine = DtlsSessionEncryptionEngine(DtlsSessionEncryptionConfig(Version.NO_ENCRYPTION))
        val plainStore = EncryptedSessionStore(delegate, plainEngine)

        plainStore.write(cid, session())
        assertArrayEquals(StoredSessionPair.srvSession, plainStore.read(cid).join()!!.sessionBlob)
    }

    // the store's throw reaches the caller wrapped by the future it came from
    private fun assertRejected(read: () -> Unit) {
        val ex = assertThrows(CompletionException::class.java, read)
        assertEquals(DtlsSessionEncryptionException::class.java, ex.cause?.javaClass)
    }

    private class CapturingSessionStore : SessionStore {
        private var item: SessionWithContext? = null

        override fun read(cid: CID): CompletableFuture<SessionWithContext?> = completedFuture(item)
        override fun write(cid: CID, session: SessionWithContext) {
            item = session
        }

        fun stored() = item
        fun flipBit(byteIdx: Int) {
            val blob = item!!.sessionBlob
            blob[byteIdx] = (blob[byteIdx].toInt() xor 0x01).toByte()
        }

        fun truncate() {
            item = item!!.copy(sessionBlob = item!!.sessionBlob.copyOf(3))
        }
    }
}
