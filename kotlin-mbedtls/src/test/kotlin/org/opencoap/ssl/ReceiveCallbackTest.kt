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

import com.sun.jna.Memory
import com.sun.jna.Pointer
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test
import org.opencoap.ssl.util.decodeToString
import org.opencoap.ssl.util.toByteBuffer
import org.opencoap.ssl.util.toMemory
import java.nio.ByteBuffer

internal class ReceiveCallbackTest {

    private val send = SendCallback

    @Test
    fun noDataAvailable() {
        val mem = Memory(100)
        val ret = ReceiveCallback.callback(Pointer.NULL, mem, 100, 0)

        assertEquals(MbedtlsApi.MBEDTLS_ERR_SSL_WANT_READ, ret)
    }

    @Test
    fun `should copy data to pointer`() {
        // given
        val buf = "dupa".toByteBuffer()
        val mem = Memory(100)

        // when
        val ret = ReceiveCallback.invoke(buf) {
            ReceiveCallback.callback(Pointer.NULL, mem, 100, 0)
        }

        // then
        assertEquals(4, ret)
        assertEquals("dupa", mem.getByteArray(0, 4).decodeToString())
    }

    @Test
    fun `should copy data to pointer - from buffer position`() {
        // given
        val buf = ByteBuffer.allocateDirect(10)
        buf.put("aaadupa".encodeToByteArray())
        buf.flip()
        buf.position(3)
        val mem = Memory(100)

        // when
        val ret = ReceiveCallback.invoke(buf) {
            ReceiveCallback.callback(Pointer.NULL, mem, 2, 0)
        }

        // then
        assertEquals(2, ret)
        assertEquals("du", mem.getByteArray(0, ret).decodeToString())

        // and
        assertEquals(MbedtlsApi.MBEDTLS_ERR_SSL_WANT_READ, ReceiveCallback.callback(Pointer.NULL, mem, 100, 0))
    }

    @Test
    fun `should return sent bytes`() {
        val sentBuf = send.invoke {
            assertEquals(4, send.callback(Pointer.NULL, "dupa".toMemory(), 4))
        }

        assertEquals("dupa", sentBuf?.decodeToString())
    }

    @Test
    fun `should sent multiple times`() {
        var index = 0
        send.invoke({ index += 1 }, {
            assertEquals(4, send.callback(Pointer.NULL, "dupa".toMemory(), 4))
            assertEquals(4, send.callback(Pointer.NULL, "dupa2".toMemory(), 4))
        })

        assertEquals(2, index)
    }

    @Test
    fun `should return failed when called outside invoke scope`() {
        assertEquals(MbedtlsApi.MBEDTLS_ERR_NET_SEND_FAILED, send.callback(Pointer.NULL, "dupa".toMemory(), 4))
    }
}
