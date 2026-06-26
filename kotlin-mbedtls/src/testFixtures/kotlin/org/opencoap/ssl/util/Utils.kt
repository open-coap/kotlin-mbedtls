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

package org.opencoap.ssl.util

import org.opencoap.ssl.transport.Transport
import org.opencoap.ssl.transport.decodeToString
import org.opencoap.ssl.transport.toByteBuffer
import java.lang.foreign.Arena
import java.lang.foreign.MemorySegment
import java.lang.foreign.ValueLayout
import java.net.InetAddress
import java.net.InetSocketAddress
import java.nio.ByteBuffer
import java.time.Duration
import java.util.concurrent.CompletableFuture
import java.util.concurrent.TimeUnit

fun localAddress(port: Int): InetSocketAddress = InetSocketAddress(InetAddress.getLocalHost(), port)

fun String.decodeHex(): ByteArray {
    check(length % 2 == 0) { "Must have an even length" }

    return chunked(2)
        .map { it.toInt(16).toByte() }
        .toByteArray()
}

fun <T> CompletableFuture<T>.await(timeout: Duration = 5.seconds): T = this.get(timeout.toMillis(), TimeUnit.MILLISECONDS)

fun String.toMemory(): MemorySegment {
    val bytes = this.encodeToByteArray()
    val segment = Arena.ofAuto().allocate(bytes.size.toLong())
    MemorySegment.copy(bytes, 0, segment, ValueLayout.JAVA_BYTE, 0L, bytes.size)
    return segment
}

fun runGC() {
    System.gc()
    Thread.sleep(10)
    System.gc()
}

val Int.seconds: Duration
    get() = Duration.ofSeconds(this.toLong())

val Int.millis: Duration
    get() = Duration.ofMillis(this.toLong())

fun <B> Transport<B>.localAddress(): InetSocketAddress = InetSocketAddress(InetAddress.getLocalHost(), this.localPort())

fun Transport<ByteBuffer>.mapToString(): Transport<String> = this.map(ByteBuffer::decodeToString, String::toByteBuffer)

// JDK8 compatible
fun ByteBuffer.flip0(): ByteBuffer {
    this.flip()
    return this
}
