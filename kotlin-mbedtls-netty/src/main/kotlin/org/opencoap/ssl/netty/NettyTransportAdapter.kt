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

import io.netty.bootstrap.Bootstrap
import io.netty.buffer.ByteBuf
import io.netty.buffer.Unpooled
import io.netty.channel.ChannelHandlerContext
import io.netty.channel.ChannelInboundHandlerAdapter
import io.netty.channel.EventLoopGroup
import io.netty.channel.nio.NioEventLoopGroup
import io.netty.channel.socket.DatagramChannel
import io.netty.channel.socket.DatagramPacket
import io.netty.channel.socket.nio.NioDatagramChannel
import io.netty.util.concurrent.DefaultThreadFactory
import org.opencoap.ssl.SslConfig
import org.opencoap.ssl.transport.Transport
import java.io.IOException
import java.net.InetSocketAddress
import java.nio.ByteBuffer
import java.time.Duration
import java.util.concurrent.CompletableFuture
import java.util.concurrent.TimeUnit

class NettyTransportAdapter(
    val channel: DatagramChannel,
    private val destinationAddress: InetSocketAddress
) : Transport<ByteBuffer> {
    private val inboundMessageReceiver = InboundMessageReceiver()

    init {
        channel.pipeline().addLast(inboundMessageReceiver)
    }

    override fun receive(timeout: Duration): CompletableFuture<ByteBuffer> {
        val promise = inboundMessageReceiver.queue.poll()

        val timeoutFuture = channel.eventLoop().schedule({ promise.cancel(false) }, timeout.toMillis(), TimeUnit.MILLISECONDS)

        return promise.whenComplete { _, _ -> timeoutFuture.cancel(false) }
    }

    override fun localPort(): Int = channel.localAddress().port

    override fun close() {
        channel.close().sync()
    }

    fun send(packet: ByteBuf): CompletableFuture<Boolean> {
        return if (channel.isActive) {
            val dgramPacket = DatagramPacket(packet, destinationAddress)
            return channel.writeAndFlush(dgramPacket).toCompletableFuture()
        } else {
            CompletableFuture<Boolean>().apply { completeExceptionally(IOException("Channel closed")) }
        }
    }

    override fun send(packet: ByteBuffer): CompletableFuture<Boolean> {
        return send(Unpooled.wrappedBuffer(packet))
    }

    companion object {
        @JvmStatic
        @JvmOverloads
        fun connect(
            sslConfig: SslConfig,
            destinationAddress: InetSocketAddress,
            group: EventLoopGroup = NioEventLoopGroup(1, DefaultThreadFactory("udp", true))
        ): NettyTransportAdapter {
            return Bootstrap()
                .group(group)
                .channel(NioDatagramChannel::class.java)
                .handler(DtlsClientHandshakeChannelHandler(sslConfig.newContext(destinationAddress), destinationAddress))
                .bind(0)
                .sync()
                .channel()
                .let { NettyTransportAdapter(it as DatagramChannel, destinationAddress) }
        }
    }

    private class InboundMessageReceiver : ChannelInboundHandlerAdapter() {
        val queue = CompletableQueue<ByteBuffer>()

        override fun channelRead(ctx: ChannelHandlerContext, msg: Any) {
            val content = (msg as DatagramPacket).content().nioBuffer()
            queue.add(content)
        }
    }
}
