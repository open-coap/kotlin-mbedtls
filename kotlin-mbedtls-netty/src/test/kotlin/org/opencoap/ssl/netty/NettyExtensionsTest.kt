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

import io.netty.buffer.Unpooled
import io.netty.channel.embedded.EmbeddedChannel
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import org.opencoap.ssl.util.await
import java.io.IOException
import java.nio.charset.Charset
import java.util.concurrent.ExecutionException

class NettyExtensionsTest {

    @Test
    fun `channelFuture to completable future`() {
        val channel = EmbeddedChannel()

        assertTrue(channel.newSucceededFuture().toCompletableFuture().await())

        val cause = assertThrows<ExecutionException> { channel.newFailedFuture(IOException("bad")).toCompletableFuture().await() }.cause
        assertTrue(cause is IOException)
    }

    @Test
    fun `channelPromise to completable future`() {
        val channel = EmbeddedChannel()

        val promise = channel.newPromise()
        val completableFuture = promise.toCompletableFuture()
        assertFalse(completableFuture.isDone)

        promise.setSuccess()
        assertTrue(completableFuture.await())
    }

    @Test
    fun `write through nioBuffer`() {
        val buf = Unpooled.buffer()

        buf.writeThroughNioBuffer {
            it.put("dupa".encodeToByteArray())
        }

        assertEquals("dupa", buf.readCharSequence(4, Charset.defaultCharset()))
    }
}
