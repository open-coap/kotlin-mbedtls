/*
 * Copyright (c) 2022 kotlin-mbedtls contributors (https://github.com/open-coap/kotlin-mbedtls)
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
import java.io.Closeable
import java.time.Duration
import java.util.concurrent.CompletableFuture
import java.util.concurrent.Executor
import java.util.function.Consumer

interface Transport<P> : TransportOutbound<P>, Closeable {
    fun receive(timeout: Duration): CompletableFuture<P>
    fun localPort(): Int

    fun <P2> map(f: (P) -> P2, f2: (P2) -> P): Transport<P2> {
        val underlying = this
        return object : Transport<P2> {
            override fun receive(timeout: Duration) = underlying.receive(timeout).thenApply(f::invoke)
            override fun send(packet: P2): CompletableFuture<Boolean> = underlying.send(f2.invoke(packet))
            override fun localPort(): Int = underlying.localPort()
            override fun close() = underlying.close()
        }
    }
}

fun interface TransportOutbound<P> {
    fun send(packet: P): CompletableFuture<Boolean>
}

fun <P, T : Transport<P>> T.listen(handler: Consumer<P>, executor: Executor = Executor(Runnable::run)): T {
    val logger = LoggerFactory.getLogger(javaClass)

    fun handle(packet: P?, err: Throwable?) {
        if (err != null) {
            logger.warn("Listener stopped: {}", err.message, err)
            return
        }

        if (packet != null) {
            try {
                handler.accept(packet)
            } catch (ex: Exception) {
                logger.error(ex.toString(), ex)
            }
        }
        // continue
        receive(Duration.ofSeconds(5)).whenCompleteAsync(::handle, executor)
    }

    // start loop
    receive(Duration.ofSeconds(5)).whenComplete(::handle)
    return this
}
