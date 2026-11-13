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
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertSame
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.time.Instant
import java.util.concurrent.CompletableFuture

class ShutdownSafeSessionStoreTest {

    private val delegate = PendingReadSessionStore()
    private val store = ShutdownSafeSessionStore(delegate)
    private val cid = byteArrayOf(1, 2, 3)
    private val session = SessionWithContext(byteArrayOf(9), mapOf("auth" to "dev-1"), Instant.ofEpochSecond(123456789))

    @Test
    fun `should pass through read completed before stopping`() {
        val read = store.read(cid)
        delegate.reads[0].complete(session)
        store.stopReading()

        assertSame(session, read.join())
        assertTrue(delegate.writes.isEmpty())
    }

    @Test
    fun `should pass through write`() {
        store.write(cid, session)

        assertEquals(listOf(cid.toList() to session), delegate.writes.map { (c, s) -> c.toList() to s })
    }

    @Test
    fun `should not read delegate once stopped`() {
        store.stopReading()

        // when
        val read = store.read(cid)

        // then, the session is left in the delegate for another server
        assertNull(read.join())
        assertTrue(delegate.reads.isEmpty())
    }

    @Test
    fun `should store back session read in flight when stopped`() {
        val read = store.read(cid)
        store.stopReading()

        // when
        delegate.reads[0].complete(session)

        // then
        assertNull(read.join())
        assertEquals(listOf(cid.toList() to session), delegate.writes.map { (c, s) -> c.toList() to s })
    }

    @Test
    fun `should not store back when read in flight finds no session`() {
        val read = store.read(cid)
        store.stopReading()

        delegate.reads[0].complete(null)

        assertNull(read.join())
        assertTrue(delegate.writes.isEmpty())
    }

    @Test
    fun `should fail read when read in flight fails`() {
        val read = store.read(cid)
        store.stopReading()

        delegate.reads[0].completeExceptionally(IllegalStateException("store failed"))

        assertTrue(read.isCompletedExceptionally)
        assertTrue(delegate.writes.isEmpty())
    }

    @Test
    fun `should fail read when delegate read throws`() {
        val failingStore = ShutdownSafeSessionStore(object : SessionStore by delegate {
            override fun read(cid: CID): CompletableFuture<SessionWithContext?> = throw IllegalStateException("store failed")
        })

        val read = failingStore.read(cid)

        assertTrue(read.isCompletedExceptionally)
    }

    @Test
    fun `should return no session when storing back fails`() {
        delegate.failWrites = true
        val read = store.read(cid)
        store.stopReading()

        delegate.reads[0].complete(session)

        assertNull(read.join())
    }

    private class PendingReadSessionStore : SessionStore {
        val reads = mutableListOf<CompletableFuture<SessionWithContext?>>()
        val writes = mutableListOf<Pair<CID, SessionWithContext>>()
        var failWrites = false

        override fun read(cid: CID): CompletableFuture<SessionWithContext?> = CompletableFuture<SessionWithContext?>().also(reads::add)

        override fun write(cid: CID, session: SessionWithContext) {
            check(!failWrites) { "store stopped" }
            writes.add(cid to session)
        }
    }
}
