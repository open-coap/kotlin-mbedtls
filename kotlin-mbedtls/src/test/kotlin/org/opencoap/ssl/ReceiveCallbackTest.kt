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

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test
import org.opencoap.ssl.transport.decodeToString
import org.opencoap.ssl.transport.toByteBuffer
import org.opencoap.ssl.util.toMemory
import java.lang.foreign.Arena
import java.lang.foreign.MemorySegment
import java.lang.foreign.ValueLayout
import java.nio.ByteBuffer

internal class ReceiveCallbackTest {

    private val send = SendCallback
    private val arena = Arena.ofAuto()

    private fun MemorySegment.readString(len: Int): String {
        val bytes = ByteArray(len)
        MemorySegment.copy(this, ValueLayout.JAVA_BYTE, 0L, bytes, 0, len)
        return bytes.decodeToString()
    }

    @Test
    fun noDataAvailable() {
        val mem = arena.allocate(100)
        val ret = ReceiveCallback.callback(MemorySegment.NULL, mem, 100, 0)

        assertEquals(MbedtlsApi.MBEDTLS_ERR_SSL_WANT_READ, ret)
    }

    @Test
    fun `should copy data to pointer`() {
        // given
        val buf = "dupa".toByteBuffer()
        val mem = arena.allocate(100)

        // when
        val ret = ReceiveCallback.invoke(buf) {
            ReceiveCallback.callback(MemorySegment.NULL, mem, 100, 0)
        }

        // then
        assertEquals(4, ret)
        assertEquals("dupa", mem.readString(4))
    }

    @Test
    fun `should copy data to pointer - from buffer position`() {
        // given
        val buf = ByteBuffer.allocateDirect(10)
        buf.put("aaadupa".encodeToByteArray())
        buf.flip()
        buf.position(3)
        val mem = arena.allocate(100)

        // when
        val ret = ReceiveCallback.invoke(buf) {
            ReceiveCallback.callback(MemorySegment.NULL, mem, 2, 0)
        }

        // then
        assertEquals(2, ret)
        assertEquals("du", mem.readString(ret))

        // and
        assertEquals(MbedtlsApi.MBEDTLS_ERR_SSL_WANT_READ, ReceiveCallback.callback(MemorySegment.NULL, mem, 100, 0))
    }

    @Test
    fun `should return sent bytes`() {
        val sentBuf = send.invoke {
            assertEquals(4, send.callback(MemorySegment.NULL, "dupa".toMemory(), 4))
        }

        assertEquals("dupa", sentBuf?.decodeToString())
    }

    @Test
    fun `should sent multiple times`() {
        var index = 0
        send.invoke({ index += 1 }, {
            assertEquals(4, send.callback(MemorySegment.NULL, "dupa".toMemory(), 4))
            assertEquals(4, send.callback(MemorySegment.NULL, "dupa2".toMemory(), 4))
        })

        assertEquals(2, index)
    }

    @Test
    fun `should return failed when called outside invoke scope`() {
        assertEquals(MbedtlsApi.MBEDTLS_ERR_NET_SEND_FAILED, send.callback(MemorySegment.NULL, "dupa".toMemory(), 4))
    }
}
