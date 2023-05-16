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

import io.netty.buffer.ByteBuf
import io.netty.buffer.ByteBufUtil
import io.netty.buffer.Unpooled
import io.netty.channel.ChannelFuture
import io.netty.util.ReferenceCounted
import org.opencoap.ssl.transport.Transport
import java.nio.ByteBuffer
import java.util.concurrent.CompletableFuture

fun ChannelFuture.toCompletableFuture(): CompletableFuture<Boolean> {
    if (this.isSuccess) return CompletableFuture.completedFuture(true)

    val promise = CompletableFuture<Boolean>()
    addListener {
        if (it.isSuccess) {
            promise.complete(true)
        } else {
            promise.completeExceptionally(it.cause())
        }
    }

    return promise
}

fun ByteBuffer.toByteBuf(): ByteBuf = Unpooled.wrappedBuffer(this)

fun ByteArray.toByteBuf(): ByteBuf = Unpooled.wrappedBuffer(this)

fun ByteBuf.toByteArray(): ByteArray {
    return ByteBufUtil.getBytes(this, readerIndex(), readableBytes(), false)
        .also { this.release() }
}

fun ByteBuf.writeThroughNioBuffer(f: (ByteBuffer) -> Unit) {
    require(this.nioBufferCount() == 1)

    val nioBuffer = this.nioBuffer(0, this.writableBytes())
    f.invoke(nioBuffer)

    this.writerIndex(nioBuffer.remaining())
}

inline fun <T : ReferenceCounted> T.useAndRelease(f: (T) -> Unit) {
    try {
        f.invoke(this)
    } finally {
        this.release()
    }
}

fun Transport<ByteBuf>.mapToByteArray(): Transport<ByteArray> = this.map(ByteBuf::toByteArray, Unpooled::wrappedBuffer)

fun Transport<ByteBuf>.mapToString(): Transport<String> = this.mapToByteArray().map(::String, String::encodeToByteArray)
