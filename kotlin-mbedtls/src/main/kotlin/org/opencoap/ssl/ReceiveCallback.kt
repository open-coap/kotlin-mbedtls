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

package org.opencoap.ssl

import com.sun.jna.Callback
import com.sun.jna.Pointer
import org.slf4j.LoggerFactory
import java.nio.ByteBuffer

internal object ReceiveCallback : Callback {

    private val logger = LoggerFactory.getLogger(javaClass)
    private val buffer = ThreadLocal<ByteBuffer>()
    private val timeout = ThreadLocal<Int>()

    operator fun <T> invoke(buf: ByteBuffer?, readFun: () -> T): T {
        this.buffer.set(buf)
        try {
            return readFun.invoke()
        } finally {
            this.buffer.remove()
            this.timeout.remove()
        }
    }

    fun timeout(): Int {
        return timeout.get() ?: 0
    }

    fun callback(ctx: Pointer?, bufPointer: Pointer, len: Int, timeout: Int): Int {
        val buffer = this.buffer.get()
        this.buffer.remove()
        this.timeout.set(timeout)
        try {
            return when {
                buffer == null -> MbedtlsApi.MBEDTLS_ERR_SSL_WANT_READ
                !buffer.hasRemaining() && timeout == 0 -> MbedtlsApi.MBEDTLS_ERR_SSL_WANT_READ
                !buffer.hasRemaining() -> MbedtlsApi.MBEDTLS_ERR_SSL_TIMEOUT

                else -> {
                    val size = buffer.remaining().coerceAtMost(len)
                    buffer.limit(buffer.position() + size)
                    bufPointer
                        .getByteBuffer(0, len.toLong())
                        .put(buffer)

                    size
                }
            }
        } catch (e: Exception) {
            // need to catch all exceptions to avoid crashing
            logger.error(e.message, e)
        }
        return MbedtlsApi.MBEDTLS_ERR_NET_RECV_FAILED
    }
}

internal typealias SendBytes = (ByteBuffer) -> Unit

internal object SendCallback : Callback {
    private val logger = LoggerFactory.getLogger(javaClass)
    private val sendFunc = ThreadLocal<SendBytes>()

    operator fun <T> invoke(send: SendBytes, run: () -> T): T {
        sendFunc.set(send)
        try {
            return run()
        } finally {
            sendFunc.remove()
        }
    }

    operator fun invoke(run: () -> Unit): ByteBuffer? {
        var sendBuf: ByteBuffer? = null
        invoke({ sendBuf = it }, run)
        return sendBuf
    }

    fun callback(ctx: Pointer?, buf: Pointer, len: Int): Int {
        try {
            sendFunc.get()?.also {
                it.invoke(buf.getByteBuffer(0, len.toLong()))
                return len
            }
        } catch (e: java.lang.Exception) {
            // need to catch all exceptions to avoid crashing
            logger.error(e.message, e)
        }
        return MbedtlsApi.MBEDTLS_ERR_NET_SEND_FAILED
    }
}
