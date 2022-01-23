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
import java.nio.ByteBuffer
import kotlin.test.Test
import kotlin.test.assertEquals


internal class ReceiveCallbackTest {

    private val recv = ReceiveCallback()

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
        recv.localReadBuffer.set(buf)

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
        recv.localReadBuffer.set(buf)

        // when
        val mem = Memory(100)
        val ret = recv.callback(Pointer.NULL, mem, 100, 0)

        // then
        assertEquals(4, ret)
        assertEquals("dupa", mem.getByteArray(0, 4).decodeToString())
    }
}