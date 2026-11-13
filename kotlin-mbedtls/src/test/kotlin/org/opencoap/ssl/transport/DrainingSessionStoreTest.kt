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
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertSame
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.time.Instant
import java.util.concurrent.CompletableFuture
import java.util.concurrent.CompletionException

class DrainingSessionStoreTest {

    private val delegate = PendingReadSessionStore()
    private val store = DrainingSessionStore(delegate)
    private val cid = byteArrayOf(1, 2, 3)
    private val session = SessionWithContext(byteArrayOf(9), mapOf("auth" to "dev-1"), Instant.ofEpochSecond(123456789))

    @Test
    fun `should pass through read completed before close`() {
        val read = store.read(cid)
        delegate.reads[0].complete(session)

        assertSame(session, read.join())
        assertTrue(store.close().isDone)
        assertTrue(delegate.writes.isEmpty())
    }

    @Test
    fun `should pass through write`() {
        store.write(cid, session)

        assertEquals(listOf(cid.toList() to session), delegate.writes.map { (c, s) -> c.toList() to s })
    }

    @Test
    fun `should not read delegate once closed`() {
        store.close()

        // when
        val read = store.read(cid)

        // then, the session is left in the delegate for another server
        assertNull(read.join())
        assertTrue(delegate.reads.isEmpty())
    }

    @Test
    fun `should store back session read in flight when closed`() {
        val read = store.read(cid)
        store.close()

        // when
        delegate.reads[0].complete(session)

        // then
        assertNull(read.join())
        assertEquals(listOf(cid.toList() to session), delegate.writes.map { (c, s) -> c.toList() to s })
    }

    @Test
    fun `should complete close only after reads in flight complete`() {
        val read1 = store.read(cid)
        val read2 = store.read(cid)

        // when
        val closed = store.close()

        // then
        assertFalse(closed.isDone)
        delegate.reads[0].complete(null)
        assertFalse(closed.isDone)
        delegate.reads[1].complete(session)
        assertTrue(closed.isDone)

        assertNull(read1.join())
        assertNull(read2.join())
        assertEquals(1, delegate.writes.size)
    }

    @Test
    fun `should have stored back the session when close completes`() {
        store.read(cid)
        val writesWhenClosed = store.close().thenApply { delegate.writes.size }

        delegate.reads[0].complete(session)

        assertEquals(1, writesWhenClosed.join())
    }

    @Test
    fun `should complete close after a read in flight fails`() {
        val read = store.read(cid)
        val closed = store.close()

        delegate.reads[0].completeExceptionally(IllegalStateException("store failed"))

        assertTrue(closed.isDone)
        assertTrue(read.isCompletedExceptionally)
        assertTrue(delegate.writes.isEmpty())
    }

    @Test
    fun `should complete close when delegate read throws`() {
        val failingStore = DrainingSessionStore(object : SessionStore by delegate {
            override fun read(cid: CID): CompletableFuture<SessionWithContext?> = throw IllegalStateException("store failed")
        })

        val read = failingStore.read(cid)

        assertTrue(read.isCompletedExceptionally)
        assertTrue(failingStore.close().isDone)
    }

    @Test
    fun `should complete close when storing back fails`() {
        delegate.failWrites = true
        val read = store.read(cid)
        val closed = store.close()

        delegate.reads[0].complete(session)

        assertNull(read.join())
        assertTrue(closed.isDone)
    }

    @Test
    fun `should be idempotent when closing`() {
        store.read(cid)
        val closed1 = store.close()
        val closed2 = store.close()
        assertFalse(closed1.isDone || closed2.isDone)

        // a caller completing its future does not complete the other ones
        closed1.completeExceptionally(CompletionException(IllegalStateException()))
        assertFalse(closed2.isDone)

        delegate.reads[0].complete(session)

        assertTrue(closed2.isDone)
        assertTrue(store.close().isDone)
        assertEquals(1, delegate.writes.size)
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
