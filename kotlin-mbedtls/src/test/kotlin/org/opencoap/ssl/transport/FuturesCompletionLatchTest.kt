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

package org.opencoap.ssl.transport

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger

class FuturesCompletionLatchTest {

    private val latch = FuturesCompletionLatch()

    @Test
    fun `should complete close immediately when nothing in flight`() {
        val closed = latch.close()

        assertTrue(closed.isDone)
        assertTrue(latch.isClosed)
    }

    @Test
    fun `should complete close only after all acquired are released`() {
        assertTrue(latch.tryAcquire())
        assertTrue(latch.tryAcquire())

        val closed = latch.close()
        assertFalse(closed.isDone)

        latch.release()
        assertFalse(closed.isDone)

        latch.release()
        assertTrue(closed.isDone)
    }

    @Test
    fun `should refuse acquire once closed`() {
        latch.close()

        assertFalse(latch.tryAcquire())
        assertTrue(latch.close().isDone)
    }

    @Test
    fun `should not be closed by releases before close`() {
        assertTrue(latch.tryAcquire())
        latch.release()

        assertFalse(latch.isClosed)
        assertTrue(latch.tryAcquire())
    }

    @Test
    fun `should be idempotent and give every caller its own future`() {
        assertTrue(latch.tryAcquire())
        val first = latch.close()
        val second = latch.close()

        first.cancel(false)
        latch.release()

        assertTrue(second.isDone)
        assertFalse(second.isCompletedExceptionally)
        assertTrue(latch.close().isDone)
    }

    @Test
    fun `should complete close when closing concurrently with acquires and releases`() {
        val executor = Executors.newFixedThreadPool(8)
        try {
            repeat(200) {
                val latch = FuturesCompletionLatch()
                val start = CountDownLatch(1)
                val acquired = AtomicInteger()
                val released = AtomicInteger()

                val workers = (1..8).map {
                    executor.submit {
                        start.await()
                        repeat(100) {
                            if (latch.tryAcquire()) {
                                acquired.incrementAndGet()
                                released.incrementAndGet()
                                latch.release()
                            }
                        }
                    }
                }
                start.countDown()
                val closed = latch.close()
                workers.forEach { it.get(5, TimeUnit.SECONDS) }

                // every acquired operation was released, so close must have completed
                closed.get(5, TimeUnit.SECONDS)
                assertEquals(acquired.get(), released.get())
                assertFalse(latch.tryAcquire())
            }
        } finally {
            executor.shutdownNow()
        }
    }
}
