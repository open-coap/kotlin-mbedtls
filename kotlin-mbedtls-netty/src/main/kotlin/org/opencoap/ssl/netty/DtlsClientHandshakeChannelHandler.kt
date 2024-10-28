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

import io.netty.channel.ChannelDuplexHandler
import io.netty.channel.ChannelHandlerContext
import io.netty.channel.ChannelPromise
import io.netty.channel.socket.DatagramPacket
import io.netty.util.concurrent.ScheduledFuture
import org.opencoap.ssl.SslConfig
import org.opencoap.ssl.SslException
import org.opencoap.ssl.SslHandshakeContext
import org.opencoap.ssl.SslSession
import org.opencoap.ssl.transport.Packet.Companion.EMPTY_BYTEBUFFER
import org.opencoap.ssl.transport.SessionWriter
import org.slf4j.LoggerFactory
import java.net.InetSocketAddress
import java.nio.ByteBuffer
import java.nio.channels.ClosedChannelException
import java.util.concurrent.TimeUnit

class DtlsClientHandshakeChannelHandler(
    sslConfig: SslConfig,
    private val sessionWriter: SessionWriter
) : ChannelDuplexHandler() {
    private val logger = LoggerFactory.getLogger(javaClass)
    private lateinit var ctx: ChannelHandlerContext
    private val outboundMessages: MutableList<Pair<DatagramPacket, ChannelPromise>> = mutableListOf()
    private var scheduledRetransmission: ScheduledFuture<*>? = null

    private val peerAddress: InetSocketAddress get() = ctx.channel().remoteAddress() as InetSocketAddress
    private val sslHandshakeContext: SslHandshakeContext by lazy { sslConfig.newContext(peerAddress) }

    private fun write(packet: ByteBuffer) {
        val dtlsPacket = DatagramPacket(packet.toByteBuf(), peerAddress)
        ctx.writeAndFlush(dtlsPacket)
    }

    override fun channelActive(ctx: ChannelHandlerContext) {
        require(ctx.channel().remoteAddress() is InetSocketAddress) { "Remote address must be defined" }
        this.ctx = ctx
        stepAndSchedule()
    }

    private fun stepAndSchedule() {
        scheduledRetransmission?.cancel(false)
        sslHandshakeContext.step(EMPTY_BYTEBUFFER, ::write)
        scheduleRetransmission()
    }

    private fun scheduleRetransmission() {
        val readTimeout = sslHandshakeContext.readTimeout
        if (!readTimeout.isZero) {
            scheduledRetransmission = ctx.executor().schedule(::stepAndSchedule, readTimeout.toMillis(), TimeUnit.MILLISECONDS)
        }
    }

    override fun channelRead(ctx: ChannelHandlerContext, msg: Any) {
        if (msg !is DatagramPacket) {
            ctx.fireChannelRead(msg)
            return
        }

        try {
            scheduledRetransmission?.cancel(false)
            val sslContext = sslHandshakeContext.step(msg.content().nioBuffer(), ::write)
            if (sslContext is SslSession) {
                ctx.channel().pipeline().replace(this, "DTLS-Client", DtlsClientChannelHandler(sslContext, sessionWriter))

                outboundMessages.forEach { (plain, promise) ->
                    ctx.channel().writeAndFlush(plain, promise)
                }
                outboundMessages.clear()
            } else {
                scheduleRetransmission()
            }
        } catch (ex: SslException) {
            // non-recoverable exception, we need to close
            logger.warn("Closing channel ({}) due to SslException: {}", ctx.channel(), ex.toString())
            ctx.channel().close()
        } finally {
            msg.release()
        }
    }

    override fun close(ctx: ChannelHandlerContext, promise: ChannelPromise) {
        sslHandshakeContext.close()
        releaseOutboundMessages()

        super.close(ctx, promise)
    }

    private fun releaseOutboundMessages() {
        outboundMessages.forEach { (plain, promise) ->
            plain.release()
            promise.setFailure(ClosedChannelException())
        }
        outboundMessages.clear()
    }

    override fun write(ctx: ChannelHandlerContext, msg: Any, promise: ChannelPromise) {
        if (msg !is DatagramPacket) {
            ctx.write(msg, promise)
            return
        }
        outboundMessages.add(Pair(msg, promise))

        if (!ctx.channel().isOpen) releaseOutboundMessages()
    }
}
