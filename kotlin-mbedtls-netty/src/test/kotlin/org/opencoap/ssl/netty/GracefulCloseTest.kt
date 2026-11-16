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

package org.opencoap.ssl.netty

import io.netty.channel.ChannelPromise
import io.netty.channel.embedded.EmbeddedChannel
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.opencoap.ssl.util.seconds
import java.util.concurrent.CompletableFuture
import java.util.concurrent.TimeUnit

class GracefulCloseTest {

    private val channel = EmbeddedChannel().apply { freezeTime() }
    private val closes = mutableListOf<ChannelPromise>()
    private val gracefulClose = GracefulClose(channel.eventLoop(), 5.seconds) { promise ->
        closes.add(promise)
        promise.setSuccess()
    }

    @AfterEach
    fun tearDown() {
        channel.finishAndReleaseAll()
    }

    @Test
    fun `should close at once when nothing is pending`() {
        val promise = channel.newPromise()

        gracefulClose.close(promise)

        assertEquals(listOf(promise), closes)
        assertTrue(promise.isSuccess)
    }

    @Test
    fun `should not wait for operation completed before close`() {
        val operation = CompletableFuture<Unit>()
        gracefulClose.track(operation)
        operation.complete(Unit)

        gracefulClose.close(channel.newPromise())

        assertEquals(1, closes.size)
    }

    @Test
    fun `should close once all tracked operations are done`() {
        // given
        val operation1 = CompletableFuture<Unit>()
        val operation2 = CompletableFuture<Unit>()
        gracefulClose.track(operation1)
        gracefulClose.track(operation2)
        val promise = channel.newPromise()

        // when
        gracefulClose.close(promise)
        operation1.complete(Unit)

        // then, still waiting for the second
        assertTrue(closes.isEmpty())
        assertFalse(promise.isDone)

        // and when, it fails
        operation2.completeExceptionally(Exception("store read failed"))

        // then
        assertEquals(listOf(promise), closes)
        assertTrue(promise.isSuccess)
    }

    @Test
    fun `should close after timeout when operation does not complete`() {
        // given
        val operation = CompletableFuture<Unit>()
        gracefulClose.track(operation)
        val promise = channel.newPromise()
        gracefulClose.close(promise)

        // when
        channel.advanceTimeBy(4999, TimeUnit.MILLISECONDS)
        channel.runScheduledPendingTasks()
        assertTrue(closes.isEmpty())

        channel.advanceTimeBy(1, TimeUnit.MILLISECONDS)
        channel.runScheduledPendingTasks()

        // then
        assertEquals(listOf(promise), closes)

        // and, a late completion does not close again
        operation.complete(Unit)
        assertEquals(1, closes.size)
    }

    @Test
    fun `should cancel timeout when operations are done`() {
        val operation = CompletableFuture<Unit>()
        gracefulClose.track(operation)
        gracefulClose.close(channel.newPromise())

        operation.complete(Unit)
        channel.advanceTimeBy(5, TimeUnit.SECONDS)
        channel.runScheduledPendingTasks()

        assertEquals(1, closes.size)
    }

    @Test
    fun `should complete every close call with the first one`() {
        // given
        val operation = CompletableFuture<Unit>()
        gracefulClose.track(operation)
        val first = channel.newPromise()
        val second = channel.newPromise()

        // when
        gracefulClose.close(first)
        gracefulClose.close(second)
        operation.complete(Unit)

        // then
        assertEquals(listOf(first), closes)
        assertTrue(first.isSuccess)
        assertTrue(second.isSuccess)
    }

    @Test
    fun `should complete close call made after closing`() {
        gracefulClose.close(channel.newPromise())
        val late = channel.newPromise()

        gracefulClose.close(late)

        assertEquals(1, closes.size)
        assertTrue(late.isSuccess)
    }

    @Test
    fun `should close with void promise`() {
        gracefulClose.close(channel.voidPromise())

        assertEquals(1, closes.size)
        assertFalse(closes[0].isVoid)
        assertTrue(closes[0].isSuccess)
    }
}
