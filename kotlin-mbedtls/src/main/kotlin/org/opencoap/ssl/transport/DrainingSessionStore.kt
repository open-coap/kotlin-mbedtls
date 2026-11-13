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

import org.slf4j.LoggerFactory
import java.util.concurrent.CompletableFuture
import java.util.concurrent.CompletableFuture.completedFuture

/**
 * Wraps a [SessionStore] so that a transport can close without losing sessions to reads that are in flight.
 *
 * A session store may remove the session it reads (eg. one shared by several servers). A read that completes after the
 * transport stored its sessions on close would leave the session nowhere. Once [close] is called:
 * - a new read returns no session without reading the delegate, the session stays there for another server,
 * - a read in flight that completes with a session writes it back to the delegate and returns no session.
 *
 * Each transport wraps the store in its own instance, so it waits only for its own reads.
 *
 * A read is released only after its result completed, so whatever the transport chained on it (like loading the
 * session) is queued before [close] completes. Once that future completes, no read hands a session to the transport
 * anymore, which is what makes it safe to store and close sessions. A read that stalls between deciding to pass a
 * session through and completing its result for longer than the transport waits for [close] is an accepted loss.
 */
class DrainingSessionStore(private val delegate: SessionStore) : SessionStore {
    private val logger = LoggerFactory.getLogger(javaClass)
    private val readsInFlight = FuturesCompletionLatch()

    override fun read(cid: CID): CompletableFuture<SessionWithContext?> {
        if (!readsInFlight.tryAcquire()) {
            logger.info("[CID:{}] DTLS session not read, session store is closing", cid.toHex())
            return completedFuture(null)
        }

        val result = CompletableFuture<SessionWithContext?>()
        readDelegate(cid).whenComplete { session: SessionWithContext?, err: Throwable? ->
            try {
                when {
                    err != null -> result.completeExceptionally(err)

                    session != null && readsInFlight.isClosed -> {
                        writeBack(cid, session)
                        result.complete(null)
                    }

                    else -> result.complete(session)
                }
            } finally {
                // only after completing the result, so that whatever its dependents schedule (like loading the session)
                // is already queued when close() completes
                readsInFlight.release()
            }
        }
        return result
    }

    override fun write(cid: CID, session: SessionWithContext) = delegate.write(cid, session)

    /**
     * Stops reading sessions from the delegate.
     *
     * Returns a future that completes once all reads in flight have completed, including writing back the sessions they
     * read. Does not close the delegate: the transport still writes its sessions to it while closing. Idempotent.
     */
    fun close(): CompletableFuture<Unit> = readsInFlight.close()

    private fun readDelegate(cid: CID): CompletableFuture<SessionWithContext?> = try {
        delegate.read(cid)
    } catch (ex: Exception) {
        CompletableFuture<SessionWithContext?>().also { it.completeExceptionally(ex) }
    }

    private fun writeBack(cid: CID, session: SessionWithContext) {
        try {
            delegate.write(cid, session)
            logger.info("[CID:{}] DTLS session read while closing, stored it back", cid.toHex())
        } catch (ex: Exception) {
            logger.error("[CID:{}] DTLS failed to store back session read while closing: {}", cid.toHex(), ex.message)
        }
    }
}
