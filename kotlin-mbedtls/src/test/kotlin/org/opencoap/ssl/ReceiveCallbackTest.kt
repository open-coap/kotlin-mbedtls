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
import com.sun.jna.Native
import com.sun.jna.Pointer
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Test
import java.nio.ByteBuffer

internal class ReceiveCallbackTest {

    private val recv = ReceiveCallback()
    private val send = SendCallback()

    @Test
    fun noDataAvailable() {
        val mem = Memory(100)
        val ret = recv.callback(Pointer.NULL, mem, 100, 0)

        assertEquals(MbedtlsApi.MBEDTLS_ERR_SSL_WANT_READ, ret)
    }

    @Test
    fun `should copy data to pointer`() {
        // given
        val buf = ByteBuffer.allocate(10)
        buf.put("dupa".encodeToByteArray())
        buf.flip()
        recv.setBuffer(buf)

        // when
        val mem = Memory(100)
        val ret = recv.callback(Pointer.NULL, mem, 100, 0)

        // then
        assertEquals(4, ret)
        assertEquals("dupa", mem.getByteArray(0, 4).decodeToString())
    }

    @Test
    fun `should copy data to pointer - from buffer position`() {
        // given
        val buf = ByteBuffer.allocate(10)
        buf.put("aaadupa".encodeToByteArray())
        buf.flip()
        buf.position(3)
        recv.setBuffer(buf)

        // when
        val mem = Memory(100)
        val ret = recv.callback(Pointer.NULL, mem, 100, 0)

        // then
        assertEquals(4, ret)
        assertEquals("dupa", mem.getByteArray(0, 4).decodeToString())

        // and
        assertEquals(MbedtlsApi.MBEDTLS_ERR_SSL_WANT_READ, recv.callback(Pointer.NULL, mem, 100, 0))
    }

    @Test
    fun `should recv callback`() {
        val mem = Memory(100)
        mem.write(0, "dupa".encodeToByteArray(), 0, 4)

        // when
        val ret = send.callback(Pointer.NULL, mem, 4)
        val ret2 = send.callback(Pointer.NULL, mem, 4)

        // then
        assertEquals(4, ret)
        assertEquals(MbedtlsApi.MBEDTLS_ERR_NET_SEND_FAILED, ret2)
        assertEquals(mem, Native.getDirectBufferPointer(send.removeBuffer()))
        // and
        assertNull(send.removeBuffer())
    }
}
