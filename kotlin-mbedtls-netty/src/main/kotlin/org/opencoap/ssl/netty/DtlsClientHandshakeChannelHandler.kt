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
import org.opencoap.ssl.SslException
import org.opencoap.ssl.SslHandshakeContext
import org.opencoap.ssl.SslSession
import org.opencoap.ssl.transport.Packet.Companion.EMPTY_BYTEBUFFER
import org.slf4j.LoggerFactory
import java.net.InetSocketAddress
import java.nio.ByteBuffer
import java.nio.channels.ClosedChannelException
import java.util.concurrent.TimeUnit

class DtlsClientHandshakeChannelHandler(
    private val sslHandshakeContext: SslHandshakeContext,
    private val peerAddress: InetSocketAddress,
    private val storeSession: (ByteArray) -> Unit
) : ChannelDuplexHandler() {
    private val logger = LoggerFactory.getLogger(javaClass)
    private lateinit var ctx: ChannelHandlerContext
    private val outboundMessages: MutableList<Pair<DatagramPacket, ChannelPromise>> = mutableListOf()
    private var scheduledRetransmission: ScheduledFuture<*>? = null

    private fun write(packet: ByteBuffer) {
        val dtlsPacket = DatagramPacket(packet.toByteBuf(), peerAddress)
        ctx.writeAndFlush(dtlsPacket)
    }

    override fun channelActive(ctx: ChannelHandlerContext) {
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
                ctx.channel().pipeline().replace(this, "DTLS-Client", DtlsClientChannelHandler(sslContext, storeSession))

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
        outboundMessages.forEach { (plain, promise) ->
            plain.release()
            promise.setFailure(ClosedChannelException())
        }
        outboundMessages.clear()

        super.close(ctx, promise)
    }

    override fun write(ctx: ChannelHandlerContext, msg: Any, promise: ChannelPromise) {
        if (msg !is DatagramPacket) {
            ctx.write(msg, promise)
            return
        }
        outboundMessages.add(Pair(msg, promise))
    }
}
