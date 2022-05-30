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

package org.opencoap.ssl

import com.sun.jna.Callback
import com.sun.jna.Pointer
import java.nio.ByteBuffer

internal class ReceiveCallback : Callback {

    private var buffer: ByteBuffer? = null

    fun setBuffer(buf: ByteBuffer) {
        buffer = buf
    }

    fun callback(ctx: Pointer?, bufPointer: Pointer, len: Int, timeout: Int): Int {
        try {
            val buffer = this.buffer
            this.buffer = null

            if (buffer == null || !buffer.hasRemaining()) {
                return MbedtlsApi.MBEDTLS_ERR_SSL_WANT_READ
            }

            val size = buffer.remaining()
            bufPointer
                .getByteBuffer(0, len.toLong())
                .put(buffer)

            return size
        } catch (e: Exception) {
            // need to catch all exceptions to avoid crashing
            e.printStackTrace()
        }
        return MbedtlsApi.MBEDTLS_ERR_NET_RECV_FAILED
    }
}

internal class SendCallback : Callback {
    private var buffer: ByteBuffer? = null

    fun removeBuffer(): ByteBuffer? {
        val buf = buffer
        buffer = null
        return buf
    }

    fun callback(ctx: Pointer?, buf: Pointer, len: Int): Int {
        try {
            if (buffer == null) {
                buffer = buf.getByteBuffer(0, len.toLong())
                return len
            }
        } catch (e: java.lang.Exception) {
            // need to catch all exceptions to avoid crashing
            e.printStackTrace()
        }
        return MbedtlsApi.MBEDTLS_ERR_NET_SEND_FAILED
    }
}
