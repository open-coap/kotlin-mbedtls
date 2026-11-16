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

import io.netty.channel.embedded.EmbeddedChannel
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertSame
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.opencoap.ssl.util.seconds
import java.util.concurrent.CompletableFuture
import java.util.concurrent.TimeUnit

class GracefulCloseTest {

    private val channel = EmbeddedChannel().apply { freezeTime() }
    private val gracefulClose = GracefulClose(channel.eventLoop(), 5.seconds)

    @AfterEach
    fun tearDown() {
        channel.finishAndReleaseAll()
    }

    @Test
    fun `should be done at once when nothing is pending`() {
        assertTrue(gracefulClose.whenDone().isDone)
    }

    @Test
    fun `should not wait for operation completed before`() {
        val operation = CompletableFuture<Unit>()
        gracefulClose.track(operation)
        operation.complete(Unit)

        assertTrue(gracefulClose.whenDone().isDone)
    }

    @Test
    fun `should be done once all tracked operations are done`() {
        // given
        val operation1 = CompletableFuture<Unit>()
        val operation2 = CompletableFuture<Unit>()
        gracefulClose.track(operation1)
        gracefulClose.track(operation2)

        // when
        val done = gracefulClose.whenDone()
        operation1.complete(Unit)

        // then, still waiting for the second
        assertFalse(done.isDone)

        // and when, it fails
        operation2.completeExceptionally(Exception("store read failed"))

        // then
        assertTrue(done.isDone && !done.isCompletedExceptionally)
    }

    @Test
    fun `should be done after timeout when operation does not complete`() {
        // given
        gracefulClose.track(CompletableFuture<Unit>())
        val done = gracefulClose.whenDone()

        // when
        channel.advanceTimeBy(4999, TimeUnit.MILLISECONDS)
        channel.runScheduledPendingTasks()
        assertFalse(done.isDone)

        channel.advanceTimeBy(1, TimeUnit.MILLISECONDS)
        channel.runScheduledPendingTasks()

        // then
        assertTrue(done.isDone && !done.isCompletedExceptionally)
    }

    @Test
    fun `should return the same future on every call`() {
        // given
        val operation = CompletableFuture<Unit>()
        gracefulClose.track(operation)

        // when
        val first = gracefulClose.whenDone()
        val second = gracefulClose.whenDone()
        operation.complete(Unit)

        // then
        assertSame(first, second)
        assertTrue(first.isDone)

        // and, a call after done gets it too
        assertSame(first, gracefulClose.whenDone())
    }
}
