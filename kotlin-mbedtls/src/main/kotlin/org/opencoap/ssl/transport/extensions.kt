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
import java.net.InetSocketAddress
import java.nio.ByteBuffer
import java.nio.channels.ClosedChannelException
import java.nio.channels.DatagramChannel
import java.nio.channels.Selector
import java.time.Duration
import java.util.concurrent.BlockingQueue
import java.util.concurrent.CompletableFuture
import java.util.concurrent.Executor
import java.util.function.Supplier

internal fun DatagramChannel.listen(bufPool: BlockingQueue<ByteBuffer>, handler: (InetSocketAddress, ByteBuffer) -> Unit) {
    val task = Runnable {
        try {
            while (this.isOpen) {
                val buffer = bufPool.take()
                buffer.clear()
                val peerAddress = this.receive(buffer) as InetSocketAddress
                buffer.flip()
                handler.invoke(peerAddress, buffer)
            }
        } catch (ex: Exception) {
            if (ex !is ClosedChannelException) LoggerFactory.getLogger(javaClass).error(ex.toString(), ex)
        }
    }

    Thread(task, "udp-io (:" + (localAddress as InetSocketAddress).port + ")").start()
}

internal fun DatagramChannel.receive(buffer: ByteBuffer, selector: Selector, timeout: Duration): InetSocketAddress? {
    buffer.clear()
    selector.select(timeout.toMillis())
    val sourceAddress = this.receive(buffer) as? InetSocketAddress
    buffer.flip()
    return sourceAddress
}

internal fun <T> Executor.supply(supplier: Supplier<T>): CompletableFuture<T> {
    return CompletableFuture.supplyAsync(supplier, this)
}

internal fun ByteArray.toHex(): String {
    return joinToString(separator = "") { eachByte -> "%02x".format(eachByte) }
}

fun ByteBuffer.copyDirect(): ByteBuffer {
    val bb = ByteBuffer.allocateDirect(this.remaining())
    bb.put(this)
    bb.flip()
    return bb
}
