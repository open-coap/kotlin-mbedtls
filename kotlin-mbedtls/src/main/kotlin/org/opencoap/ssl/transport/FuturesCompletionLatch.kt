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

import java.util.concurrent.CompletableFuture
import java.util.concurrent.atomic.AtomicInteger
import java.util.function.Function

/**
 * Counts operations in flight, and lets a caller wait for them to complete while refusing new ones.
 *
 * Thread-safe and lock-free: the closed flag and the count share one atomic value, so every decision is taken on a
 * single consistent state.
 */
internal class FuturesCompletionLatch {
    // bit 0: closed, remaining bits: number of operations in flight
    private val state = AtomicInteger()
    private val drained = CompletableFuture<Unit>()

    /**
     * Starts an operation. Returns false once closed. When it returns true, the caller must call [release] exactly once.
     */
    fun tryAcquire(): Boolean = state.getAndUpdate { if (it and CLOSED == 0) it + ONE else it } and CLOSED == 0

    /**
     * Completes an operation started with [tryAcquire].
     */
    fun release() {
        if (state.addAndGet(-ONE) == CLOSED) drained.complete(Unit)
    }

    val isClosed: Boolean
        get() = state.get() and CLOSED != 0

    /**
     * Refuses new operations. Returns a future that completes once all operations in flight are released. Idempotent.
     */
    fun close(): CompletableFuture<Unit> {
        if (state.updateAndGet { it or CLOSED } == CLOSED) drained.complete(Unit)

        // a new future for every caller, so that completing it does not affect others
        return drained.thenApply(Function.identity())
    }

    private companion object {
        const val CLOSED = 1
        const val ONE = 2
    }
}
