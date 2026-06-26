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

package org.opencoap.ssl.jna

import com.sun.jna.Memory
import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test
import java.nio.ByteBuffer

internal class CloneToMemoryTest {

    @Test
    fun `should clone buffer to memory`() {
        val originalData = byteArrayOf(1, 2, 3, 4, 5)
        val byteBuffer = ByteBuffer.wrap(originalData)

        val originalPosition = byteBuffer.position()
        val originalLimit = byteBuffer.limit()
        val originalCapacity = byteBuffer.capacity()

        val memory: Memory = byteBuffer.cloneToMemory()

        val clonedData = ByteArray(originalData.size)
        memory.read(0, clonedData, 0, originalData.size)
        assertArrayEquals(originalData, clonedData)

        assertEquals(originalPosition, byteBuffer.position(), "Buffer position should not change")
        assertEquals(originalLimit, byteBuffer.limit(), "Buffer limit should not change")
        assertEquals(originalCapacity, byteBuffer.capacity(), "Buffer capacity should not change")
    }
}
