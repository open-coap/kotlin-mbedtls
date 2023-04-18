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

package org.opencoap.ssl.transport

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.nio.ByteBuffer

class BytesExtensionsTest {

    @Test
    fun `should copy ByteBuffer`() {
        verifyCopy(ByteBuffer.allocateDirect(100))
        verifyCopy(ByteBuffer.allocate(100))
    }

    private fun verifyCopy(bb: ByteBuffer) {
        bb.put(" dupa".encodeToByteArray())
        bb.flip()
        bb.position(1)

        // when
        val cpBuf = bb.copy()

        // then
        assertEquals("dupa", cpBuf.decodeToString())
        assertEquals(4, cpBuf.capacity())
    }

    @Test
    fun `buffer isNotEmpty`() {
        val buf = ByteBuffer.allocate(12)
        assertTrue(buf.isNotEmpty())
        buf.putInt(321)
        buf.flip()
        assertTrue(buf.isNotEmpty())
    }

    @Test
    fun `buffer isEmpty`() {
        val buf = ByteBuffer.allocate(0)
        assertTrue(buf.isEmpty())

        val buf2 = ByteBuffer.allocate(10)
        buf2.position(10)
        assertTrue(buf2.isEmpty())
    }

    @Test
    fun `buffer decodeToString`() {
        val buf = "__dupa".toByteBuffer()
        assertEquals("__dupa", buf.decodeToString())
        assertTrue(buf.isEmpty())

        buf.position(2)
        assertEquals("dupa", buf.decodeToString())
    }
}
