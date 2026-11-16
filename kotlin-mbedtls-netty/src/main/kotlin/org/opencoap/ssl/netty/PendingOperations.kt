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

package org.opencoap.ssl.netty

import java.time.Duration
import java.util.concurrent.CompletableFuture
import java.util.concurrent.ScheduledExecutorService
import java.util.concurrent.TimeUnit

/**
 * Not thread safe, [track] and [whenDone] must be called from [executor], a tracked operation may complete on any thread.
 * Follows the graceful shutdown of Netty's Http2ConnectionHandler.
 */
internal class PendingOperations(private val executor: ScheduledExecutorService) {
    private var pending = 0
    private var waiting = false
    private val done = CompletableFuture<Boolean>()

    fun track(operation: CompletableFuture<*>) {
        pending++
        // a failed operation completes on the thread that failed it, eg. a session store thread
        operation.whenCompleteAsync({ _, _ -> if (--pending == 0 && waiting) done.complete(true) }, executor)
    }

    // true once all tracked operations are done, false after timeout; a later call gets the same future
    fun whenDone(timeout: Duration): CompletableFuture<Boolean> {
        if (!waiting) {
            // scheduled first, a rejected timeout must not leave a future that never completes
            if (pending > 0) executor.schedule({ done.complete(false) }, timeout.toMillis(), TimeUnit.MILLISECONDS)
            waiting = true
            if (pending == 0) done.complete(true)
        }
        return done
    }
}
