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

package org.opencoap.ssl

import org.slf4j.LoggerFactory
import java.nio.ByteBuffer

internal typealias SendBytes = (ByteBuffer) -> Unit

/**
 * Per-context bridge for the mbedtls BIO callbacks.
 *
 * Core owns the receive/send orchestration here (the WANT_READ / TIMEOUT dance, capturing sent bytes);
 * the engine merely wires the native callbacks to [onReceive] / [onSend], passing heap/direct
 * [ByteBuffer] views over native memory so this class stays free of native types.
 */
class Bio {
    private val logger = LoggerFactory.getLogger(javaClass)
    private val receiveBuffer = ThreadLocal<ByteBuffer?>()
    private val sendFunc = ThreadLocal<SendBytes?>()
    private val lastTimeout = ThreadLocal<Int>()

    fun <T> withReceive(buf: ByteBuffer?, block: () -> T): T {
        receiveBuffer.set(buf)
        try {
            return block()
        } finally {
            receiveBuffer.remove()
            lastTimeout.remove()
        }
    }

    fun <T> withSend(send: SendBytes, block: () -> T): T {
        sendFunc.set(send)
        try {
            return block()
        } finally {
            sendFunc.remove()
        }
    }

    /** Runs [block], returning the single buffer mbedtls handed to the send callback (or null). */
    fun captureSend(block: () -> Unit): ByteBuffer? {
        var sendBuf: ByteBuffer? = null
        withSend({ sendBuf = it }, block)
        return sendBuf
    }

    /** Retransmission timeout (ms) mbedtls requested during the last receive callback. */
    fun timeout(): Int = lastTimeout.get() ?: 0

    /**
     * Invoked by the engine's native receive callback. [dst] is a view over native memory with capacity [len].
     * Returns the number of bytes copied, or an mbedtls error code.
     */
    fun onReceive(dst: ByteBuffer, len: Int, timeout: Int): Int {
        val buffer = this.receiveBuffer.get()
        this.receiveBuffer.set(null)
        this.lastTimeout.set(timeout)
        try {
            return when {
                buffer == null -> Mbedtls.MBEDTLS_ERR_SSL_WANT_READ
                !buffer.hasRemaining() && timeout == 0 -> Mbedtls.MBEDTLS_ERR_SSL_WANT_READ
                !buffer.hasRemaining() -> Mbedtls.MBEDTLS_ERR_SSL_TIMEOUT

                else -> {
                    val size = buffer.remaining().coerceAtMost(len)
                    buffer.limit(buffer.position() + size)
                    dst.put(buffer)
                    size
                }
            }
        } catch (e: Exception) {
            // need to catch all exceptions to avoid crashing native code
            logger.error(e.message, e)
        }
        return Mbedtls.MBEDTLS_ERR_NET_RECV_FAILED
    }

    /**
     * Invoked by the engine's native send callback. [src] is a view over native memory of length [len].
     * Returns [len] on success, or an mbedtls error code.
     */
    fun onSend(src: ByteBuffer, len: Int): Int {
        try {
            sendFunc.get()?.also {
                it.invoke(src)
                return len
            }
        } catch (e: Exception) {
            // need to catch all exceptions to avoid crashing native code
            logger.error(e.message, e)
        }
        return Mbedtls.MBEDTLS_ERR_NET_SEND_FAILED
    }
}
