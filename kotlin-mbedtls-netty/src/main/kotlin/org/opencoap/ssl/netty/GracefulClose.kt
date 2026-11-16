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

import io.netty.channel.ChannelPromise
import io.netty.util.concurrent.EventExecutor
import io.netty.util.concurrent.PromiseNotifier
import org.slf4j.LoggerFactory
import java.time.Duration
import java.util.concurrent.CompletableFuture
import java.util.concurrent.Future
import java.util.concurrent.TimeUnit

/**
 * Not thread safe, must be used only from [executor]. Follows the graceful shutdown of Netty's Http2ConnectionHandler.
 */
internal class GracefulClose(
    private val executor: EventExecutor,
    private val timeout: Duration,
    private val doClose: (ChannelPromise) -> Unit
) {
    private val logger = LoggerFactory.getLogger(javaClass)

    private var pending = 0
    private var promise: ChannelPromise? = null
    private var timeoutTask: Future<*>? = null
    private var closed = false

    fun track(operation: CompletableFuture<*>) {
        pending++
        operation.whenComplete { _, _ -> operationDone() }
    }

    fun close(promise: ChannelPromise) {
        val closing = this.promise
        if (closing != null) {
            PromiseNotifier.cascade(closing, promise.unvoid())
            return
        }

        this.promise = promise.unvoid()
        if (pending == 0) {
            closeNow()
        } else {
            timeoutTask = executor.schedule(::closeAfterTimeout, timeout.toMillis(), TimeUnit.MILLISECONDS)
        }
    }

    private fun operationDone() {
        pending--
        if (promise != null && pending == 0) closeNow()
    }

    private fun closeAfterTimeout() {
        logger.warn("Closing after {}ms timeout, {} operations still pending", timeout.toMillis(), pending)
        closeNow()
    }

    private fun closeNow() {
        if (closed) return
        closed = true
        timeoutTask?.cancel(false)
        doClose(promise!!)
    }
}
