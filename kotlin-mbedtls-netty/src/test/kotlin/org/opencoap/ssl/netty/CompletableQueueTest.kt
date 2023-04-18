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

package org.opencoap.ssl.netty

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Test

class CompletableQueueTest {

    private val queue = CompletableQueue<String>()

    @Test
    fun `poll on empty queue`() {
        val promise1 = queue.poll()
        val promise2 = queue.poll()
        assertFalse(promise1.isDone)
        assertFalse(promise2.isDone)

        // when
        queue.add("foo 1")

        // then
        assertEquals("foo 1", promise1.join())
        assertFalse(promise2.isDone)

        // and
        queue.add("foo 2")
        queue.add("foo 3")
        assertEquals("foo 2", promise2.join())
        assertEquals("foo 3", queue.poll().join())
    }
}
