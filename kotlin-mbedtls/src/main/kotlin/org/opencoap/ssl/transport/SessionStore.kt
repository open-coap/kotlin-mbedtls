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

import java.time.Instant
import java.util.concurrent.CompletableFuture
import java.util.concurrent.CompletableFuture.completedFuture
import java.util.concurrent.ConcurrentHashMap

typealias CID = ByteArray

/**
 * Holds DTLS sessions that are not currently live, so a record arriving for a known CID can resume
 * one instead of forcing a new handshake. Typically backed by Redis, DynamoDB or similar.
 *
 * **The store is a trust boundary.** [SessionWithContext.sessionBlob] comes from mbedTLS'
 * context-save format, which has neither confidentiality nor integrity of its own:
 *
 * - It carries the session master secret, so whoever can read it can decrypt the session's traffic.
 * - It has no authentication tag, and the library cannot tell a modified blob from an intact one.
 *   A third of single-bit flips load and yield a fully working session, silently.
 *
 * Both are therefore the store's to provide. [DtlsSessionEncryptionEngine] supplies them.
 *
 * [read] is expected to remove the entry it returns: a session is either live in a server or parked
 * in the store, never both.
 */
interface SessionStore {
    fun read(cid: CID): CompletableFuture<SessionWithContext?>
    fun write(cid: CID, session: SessionWithContext)
}

/** A parked DTLS session. [sessionBlob] contains key material — see [SessionStore]. */
data class SessionWithContext(
    val sessionBlob: ByteArray,
    val authenticationContext: AuthenticationContext,
    val sessionStartTimestamp: Instant
)

fun interface SessionWriter {
    operator fun invoke(cid: CID, session: ByteArray)

    companion object {
        @JvmField
        val NO_OPS: SessionWriter = SessionWriter { _, _ -> }
    }
}

object NoOpsSessionStore : SessionStore {
    override fun read(cid: CID): CompletableFuture<SessionWithContext?> = completedFuture(null)
    override fun write(cid: CID, session: SessionWithContext) = Unit
}

class HashMapSessionStore : SessionStore {
    private val map = ConcurrentHashMap<String, SessionWithContext>()

    override fun read(cid: CID): CompletableFuture<SessionWithContext?> = completedFuture(map.remove(cid.toHex()))

    override fun write(cid: CID, session: SessionWithContext) {
        map.put(cid.toHex(), session)
    }

    fun clear() = map.clear()
    fun size() = map.size
}
