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

import com.sun.jna.Memory
import com.sun.jna.Native
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test
import java.nio.ByteBuffer
import java.nio.ByteOrder

class NativeTypesTest {

    @Test
    fun `should match the platform size_t width`() {
        // fails loudly if this library ever ships a native library for a 32 bit target
        assertEquals(Native.SIZE_T_SIZE.toLong(), SIZE_T_LEN)
    }

    @Test
    fun `should read size_t out-parameter`() {
        Memory(SIZE_T_LEN).use { mem ->
            mem.setLong(0, 1280)

            assertEquals(1280, mem.getSizeT())
        }
    }

    @Test
    fun `should read size_t larger than the old two byte parse allowed`() {
        Memory(SIZE_T_LEN).use { mem ->
            mem.setLong(0, 70_000)

            assertEquals(70_000, mem.getSizeT())
        }
    }

    @Test
    fun `should read size_t at given offset`() {
        Memory(16).use { mem ->
            mem.clear()
            mem.setLong(8, 64)

            assertEquals(0, mem.getSizeT())
            assertEquals(64, mem.getSizeT(8))
        }
    }

    @Test
    fun `should read size_t in native byte order`() {
        // the byte layout mbedtls writes for a size_t on this platform
        val nativeBytes = ByteBuffer.allocate(SIZE_T_LEN.toInt())
            .order(ByteOrder.nativeOrder())
            .putLong(1280)
            .array()

        Memory(SIZE_T_LEN).use { mem ->
            mem.write(0, nativeBytes, 0, nativeBytes.size)

            assertEquals(1280, mem.getSizeT())
        }
    }
}
