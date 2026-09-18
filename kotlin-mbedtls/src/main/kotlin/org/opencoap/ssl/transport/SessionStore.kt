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
 * Holds DTLS sessions that are not currently live, so that a record arriving for a known CID can
 * resume a session instead of forcing a new handshake. Implementations are typically backed by
 * shared infrastructure such as Redis or DynamoDB.
 *
 * **The store is a trust boundary.** [SessionWithContext.sessionBlob] is produced by mbedTLS'
 * context-save format, which provides neither confidentiality nor integrity of its own, so both
 * are the store's responsibility:
 *
 * - **Confidentiality.** The blob carries the session's key material, including the master secret.
 *   Anyone who can read it can decrypt the session's traffic. Treat it as you would a private key:
 *   encrypt it at rest and in transit, and keep it out of logs, backups and crash dumps that are
 *   not protected to the same standard.
 *
 * - **Integrity.** The blob has no authentication tag, and the library cannot tell a modified blob
 *   from an intact one. Measured on an exhaustive single-bit sweep of a 235-byte session blob,
 *   623 of 1880 flips (33%) were accepted by the load path and produced a fully working session
 *   carrying correct plaintext; the tampering was absorbed silently. Anyone who can write to the
 *   store can therefore alter live session state. The store must authenticate what it returns, and
 *   must not be writable by anything other than the servers that own these sessions.
 *
 * [DtlsSessionEncryptionEngine] provides both properties: it seals the blob in an AES-GCM envelope
 * under an application-held key, so a modified blob fails the tag check instead of being opened.
 *
 * [read] is expected to remove the entry it returns: a session is either live in a server or
 * parked in the store, never both.
 */
interface SessionStore {
    fun read(cid: CID): CompletableFuture<SessionWithContext?>
    fun write(cid: CID, session: SessionWithContext)
}

/**
 * A parked DTLS session. [sessionBlob] contains key material — see [SessionStore] for the
 * confidentiality and integrity properties a store must provide.
 */
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
