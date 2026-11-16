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

import org.slf4j.LoggerFactory
import java.time.Duration
import java.util.concurrent.CompletableFuture
import java.util.concurrent.Future
import java.util.concurrent.ScheduledExecutorService
import java.util.concurrent.TimeUnit

/**
 * Not thread safe, must be used only from [executor]. Follows the graceful shutdown of Netty's Http2ConnectionHandler.
 */
internal class PendingOperations(private val executor: ScheduledExecutorService) {
    private val logger = LoggerFactory.getLogger(javaClass)

    private var pending = 0
    private var done: CompletableFuture<Unit>? = null
    private var timeoutTask: Future<*>? = null

    fun <T> track(operation: CompletableFuture<T>): CompletableFuture<T> {
        pending++
        operation.whenComplete { _, _ -> operationDone() }
        return operation
    }

    // a later call gets the same future, the timeout of the first call applies
    fun whenDone(timeout: Duration): CompletableFuture<Unit> {
        done?.let { return it }

        val future = CompletableFuture<Unit>()
        done = future
        if (pending == 0) {
            complete()
        } else {
            timeoutTask = executor.schedule(Runnable { completeAfterTimeout(timeout) }, timeout.toMillis(), TimeUnit.MILLISECONDS)
        }
        return future
    }

    private fun operationDone() {
        pending--
        if (pending == 0) complete()
    }

    private fun completeAfterTimeout(timeout: Duration) {
        logger.warn("Stopped waiting after {}ms timeout, {} operations still pending", timeout.toMillis(), pending)
        complete()
    }

    private fun complete() {
        val future = done ?: return
        timeoutTask?.cancel(false)
        future.complete(Unit)
    }
}
