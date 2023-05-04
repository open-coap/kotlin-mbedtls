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
import org.opencoap.ssl.SslConfig
import org.opencoap.ssl.transport.ByteBufferPacket
import org.opencoap.ssl.transport.DtlsServer
import org.opencoap.ssl.transport.Packet
import java.nio.ByteBuffer
import java.util.concurrent.CompletableFuture
import java.util.concurrent.CompletableFuture.completedFuture

class DtlsChannelHandler(private val sslConfig: SslConfig) : ChannelDuplexHandler() {
    private lateinit var ctx: ChannelHandlerContext
    lateinit var dtlsServer: DtlsServer

    private fun write(packet: ByteBufferPacket): CompletableFuture<Boolean> {
        val dtlsPacket = DatagramPacket(packet.buffer.toByteBuf(), packet.peerAddress)

        if (!ctx.channel().isWritable) {
            return completedFuture(false)
        }
        return ctx.writeAndFlush(dtlsPacket).toCompletableFuture()
    }

    override fun handlerAdded(ctx: ChannelHandlerContext) {
        this.ctx = ctx
        this.dtlsServer = DtlsServer(::write, sslConfig, executor = ctx.executor())
    }

    override fun channelRead(ctx: ChannelHandlerContext, msg: Any) {
        if (msg !is DatagramPacket) {
            ctx.fireChannelRead(msg)
            return
        }

        msg.useAndRelease {
            dtlsServer.handleReceived(msg.sender(), msg.content().nioBuffer())
                .thenAccept {
                    if (it != Packet.EmptyByteBufferPacket) {
                        ctx.fireChannelRead(DatagramPacketWithContext.from(it))
                    }
                }
        }
    }

    override fun write(ctx: ChannelHandlerContext, msg: Any, promise: ChannelPromise) {
        when (msg) {
            is DatagramPacket -> write(msg, promise, ctx)
            is SessionAuthenticationContext -> {
                dtlsServer.putSessionAuthenticationContext(msg.adr, msg.key, msg.value)
                promise.setSuccess()
            }

            else -> ctx.write(msg, promise)
        }
    }

    private fun write(msg: DatagramPacket, promise: ChannelPromise, ctx: ChannelHandlerContext) {
        msg.useAndRelease {
            val plainContent = msg.content().nioBuffer()
            val encPacket: ByteBuffer? = dtlsServer.encrypt(plainContent, msg.recipient())

            when (encPacket) {
                null -> promise.setFailure(Exception("Session not found"))
                else -> ctx.write(DatagramPacket(encPacket.toByteBuf(), msg.recipient()), promise)
            }
        }
    }
}
