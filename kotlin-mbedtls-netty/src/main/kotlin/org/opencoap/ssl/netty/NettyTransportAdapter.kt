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
import io.netty.channel.ChannelHandlerContext
import io.netty.channel.ChannelInboundHandlerAdapter
import io.netty.channel.EventLoopGroup
import io.netty.channel.MultiThreadIoEventLoopGroup
import io.netty.channel.nio.NioIoHandler
import io.netty.channel.socket.DatagramChannel
import io.netty.channel.socket.DatagramPacket
import io.netty.channel.socket.nio.NioDatagramChannel
import io.netty.util.concurrent.DefaultThreadFactory
import org.opencoap.ssl.SslConfig
import org.opencoap.ssl.SslSession
import org.opencoap.ssl.transport.SessionWriter
import org.opencoap.ssl.transport.Transport
import java.io.IOException
import java.net.InetSocketAddress
import java.time.Duration
import java.util.concurrent.CompletableFuture
import java.util.concurrent.TimeUnit

class NettyTransportAdapter(
    val channel: DatagramChannel,
    private val destinationAddress: InetSocketAddress
) : Transport<ByteBuf> {
    private val inboundMessageReceiver = InboundMessageReceiver()

    init {
        channel.pipeline().addLast(inboundMessageReceiver)
    }

    override fun receive(timeout: Duration): CompletableFuture<ByteBuf> {
        if (!channel.isActive) {
            return CompletableFuture<ByteBuf>().apply { completeExceptionally(IOException("Channel closed")) }
        }

        val promise = inboundMessageReceiver.queue.poll()

        val timeoutFuture = channel.eventLoop().schedule({ promise.cancel(false) }, timeout.toMillis(), TimeUnit.MILLISECONDS)

        return promise.whenComplete { _, _ -> timeoutFuture.cancel(false) }
    }

    override fun localPort(): Int = channel.localAddress().port

    override fun close() {
        channel.close().sync()
    }

    override fun send(packet: ByteBuf): CompletableFuture<Boolean> {
        val dgramPacket = DatagramPacket(packet, destinationAddress)
        return channel.writeAndFlush(dgramPacket).toCompletableFuture()
    }

    companion object {
        @JvmStatic
        @JvmOverloads
        fun connect(
            sslConfig: SslConfig,
            destinationAddress: InetSocketAddress,
            group: EventLoopGroup = MultiThreadIoEventLoopGroup(
                1,
                DefaultThreadFactory("udp", true),
                NioIoHandler.newFactory()
            ),
            sessionWriter: SessionWriter = SessionWriter.NO_OPS,
            bootstrapConfig: (Bootstrap) -> Unit = {},
        ): NettyTransportAdapter {
            return Bootstrap()
                .group(group)
                .channel(NioDatagramChannel::class.java)
                .handler(DtlsClientHandshakeChannelHandler(sslConfig, sessionWriter))
                .also(bootstrapConfig)
                .connect(destinationAddress)
                .sync()
                .channel()
                .let { NettyTransportAdapter(it as DatagramChannel, destinationAddress) }
        }

        fun reload(
            sslSession: SslSession,
            destinationAddress: InetSocketAddress,
            sessionWriter: SessionWriter,
            group: EventLoopGroup = MultiThreadIoEventLoopGroup(
                1,
                DefaultThreadFactory("udp", true),
                NioIoHandler.newFactory()
            ),
        ): NettyTransportAdapter {
            return Bootstrap()
                .group(group)
                .channel(NioDatagramChannel::class.java)
                .handler(DtlsClientChannelHandler(sslSession, sessionWriter))
                .bind(0)
                .sync()
                .channel()
                .let { NettyTransportAdapter(it as DatagramChannel, destinationAddress) }
        }
    }

    private class InboundMessageReceiver : ChannelInboundHandlerAdapter() {
        val queue = CompletableQueue<ByteBuf>()

        override fun channelRead(ctx: ChannelHandlerContext, msg: Any) {
            queue.add((msg as DatagramPacket).content())
        }

        override fun channelInactive(ctx: ChannelHandlerContext) {
            ctx.fireChannelInactive()
            queue.cancelAll()
        }
    }
}
