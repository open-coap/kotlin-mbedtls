/*
 * Copyright (c) 2022-2023 kotlin-mbedtls contributors (https://github.com/open-coap/kotlin-mbedtls)
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

import java.util.concurrent.CompletableFuture
import java.util.concurrent.CompletableFuture.completedFuture
import java.util.concurrent.ConcurrentHashMap

interface SessionStore {
    fun read(cid: ByteArray): CompletableFuture<SessionWithContext?>
    fun write(cid: ByteArray, session: SessionWithContext)
}

data class SessionWithContext(
    val sessionBlob: ByteArray,
    val authenticationContext: AuthenticationContext
)

object NoOpsSessionStore : SessionStore {
    override fun read(cid: ByteArray): CompletableFuture<SessionWithContext?> = completedFuture(null)
    override fun write(cid: ByteArray, session: SessionWithContext) = Unit
}

class HashMapSessionStore : SessionStore {
    private val map = ConcurrentHashMap<String, SessionWithContext>()

    override fun read(cid: ByteArray): CompletableFuture<SessionWithContext?> =
        completedFuture(map.remove(cid.toHex()))

    override fun write(cid: ByteArray, session: SessionWithContext) {
        map.put(cid.toHex(), session)
    }

    fun clear() = map.clear()
    fun size() = map.size
}
