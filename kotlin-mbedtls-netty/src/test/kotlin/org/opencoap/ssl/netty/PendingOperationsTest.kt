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
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertSame
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Test
import org.opencoap.ssl.util.seconds
import java.util.concurrent.CompletableFuture
import java.util.concurrent.CompletableFuture.completedFuture
import java.util.concurrent.Executors
import java.util.concurrent.RejectedExecutionException
import java.util.concurrent.TimeUnit
import kotlin.concurrent.thread

class PendingOperationsTest {

    private val channel = EmbeddedChannel().apply { freezeTime() }
    private val pendingOperations = PendingOperations(channel.eventLoop())

    @AfterEach
    fun tearDown() {
        channel.finishAndReleaseAll()
    }

    @Test
    fun `should be done at once when nothing is pending`() {
        assertEquals(true, pendingOperations.whenDone(5.seconds).getNow(null))
    }

    @Test
    fun `should not wait for operation completed before`() {
        val operation = CompletableFuture<Unit>()
        pendingOperations.track(operation)
        operation.complete(Unit)
        channel.runPendingTasks()

        assertEquals(true, pendingOperations.whenDone(5.seconds).getNow(null))
    }

    @Test
    fun `should not wait for operation already completed when tracked`() {
        pendingOperations.track(completedFuture(Unit))
        channel.runPendingTasks()

        assertEquals(true, pendingOperations.whenDone(5.seconds).getNow(null))
    }

    @Test
    fun `should be done once all tracked operations are done`() {
        // given
        val operation1 = CompletableFuture<Unit>()
        val operation2 = CompletableFuture<Unit>()
        pendingOperations.track(operation1)
        pendingOperations.track(operation2)

        // when
        val done = pendingOperations.whenDone(5.seconds)
        operation1.complete(Unit)
        channel.runPendingTasks()

        // then, still waiting for the second
        assertFalse(done.isDone)

        // and when, it fails
        operation2.completeExceptionally(Exception("store read failed"))
        channel.runPendingTasks()

        // then
        assertEquals(true, done.getNow(null))

        // and, the timeout firing later changes nothing
        channel.advanceTimeBy(5, TimeUnit.SECONDS)
        channel.runScheduledPendingTasks()
        assertEquals(true, done.getNow(null))
    }

    @Test
    fun `should wait for operation tracked while waiting`() {
        // given
        val operation1 = CompletableFuture<Unit>()
        pendingOperations.track(operation1)
        val done = pendingOperations.whenDone(5.seconds)

        // when
        val operation2 = CompletableFuture<Unit>()
        pendingOperations.track(operation2)
        operation1.complete(Unit)
        channel.runPendingTasks()

        // then, still waiting for the one tracked later
        assertFalse(done.isDone)

        // and when
        operation2.complete(Unit)
        channel.runPendingTasks()

        // then
        assertEquals(true, done.getNow(null))
    }

    @Test
    fun `should be done after timeout when operation does not complete`() {
        // given
        val operation = CompletableFuture<Unit>()
        pendingOperations.track(operation)
        val done = pendingOperations.whenDone(5.seconds)

        // when, just before the timeout
        channel.advanceTimeBy(4999, TimeUnit.MILLISECONDS)
        channel.runScheduledPendingTasks()

        // then, still waiting
        assertFalse(done.isDone)

        // and when, the timeout elapses
        channel.advanceTimeBy(1, TimeUnit.MILLISECONDS)
        channel.runScheduledPendingTasks()

        // then, timed out
        assertEquals(false, done.getNow(null))

        // and, a late completion changes nothing
        operation.complete(Unit)
        channel.runPendingTasks()
        assertEquals(false, done.getNow(null))
    }

    @Test
    fun `should return the same future on every call`() {
        // given
        val operation = CompletableFuture<Unit>()
        pendingOperations.track(operation)

        // when
        val first = pendingOperations.whenDone(5.seconds)
        val second = pendingOperations.whenDone(5.seconds)
        operation.complete(Unit)
        channel.runPendingTasks()

        // then
        assertSame(first, second)
        assertEquals(true, first.getNow(null))

        // and, a call after done gets it too
        assertSame(first, pendingOperations.whenDone(5.seconds))
    }

    @Test
    fun `should count operation completed on another thread on the executor`() {
        // given, an operation tracked on the executor, eg. a session store read
        val executor = Executors.newSingleThreadScheduledExecutor { Thread(it, "executor") }
        val pendingOperations = PendingOperations(executor)
        val operation = CompletableFuture<Unit>()
        val done = executor.submit<CompletableFuture<Boolean>> {
            pendingOperations.track(operation)
            pendingOperations.whenDone(5.seconds)
        }.get()
        val doneOnThread = done.thenApply { Thread.currentThread().name }

        // when, it fails on the thread of the store
        thread(name = "store-thread") { operation.completeExceptionally(Exception("store read failed")) }.join()

        // then
        assertEquals("executor", doneOnThread.get(5, TimeUnit.SECONDS))

        executor.shutdown()
    }

    @Test
    fun `should not return a future that never completes when timeout cannot be scheduled`() {
        // given
        val executor = Executors.newSingleThreadScheduledExecutor().apply { shutdown() }
        val pendingOperations = PendingOperations(executor)
        pendingOperations.track(CompletableFuture<Unit>())

        // when, the timeout is rejected
        assertThrows(RejectedExecutionException::class.java) { pendingOperations.whenDone(5.seconds) }

        // and, a later call fails too
        assertThrows(RejectedExecutionException::class.java) { pendingOperations.whenDone(5.seconds) }
    }
}
