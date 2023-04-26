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

import com.sun.jna.Memory
import org.opencoap.ssl.transport.Transport
import java.net.InetAddress
import java.net.InetSocketAddress
import java.nio.ByteBuffer
import java.time.Duration
import java.util.concurrent.CompletableFuture
import java.util.concurrent.TimeUnit

fun localAddress(port: Int): InetSocketAddress {
    return InetSocketAddress(InetAddress.getLocalHost(), port)
}

fun String.decodeHex(): ByteArray {
    check(length % 2 == 0) { "Must have an even length" }

    return chunked(2)
        .map { it.toInt(16).toByte() }
        .toByteArray()
}

fun String.toByteBuffer(): ByteBuffer = this.encodeToByteArray().asByteBuffer()

fun ByteArray.asByteBuffer(): ByteBuffer = ByteBuffer.wrap(this)

fun <T> CompletableFuture<T>.await(): T {
    return this.get(5, TimeUnit.SECONDS)
}

fun ByteBuffer.decodeToString(): String {
    val bb = ByteArray(this.remaining())
    this.get(bb)
    return bb.decodeToString()
}

fun String.toMemory(): Memory {
    return Memory(this.length.toLong()).also {
        it.write(0, this.encodeToByteArray(), 0, this.length)
    }
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

fun <B> Transport<B>.localAddress(): InetSocketAddress =
    InetSocketAddress(InetAddress.getLocalHost(), this.localPort())
