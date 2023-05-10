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
import org.opencoap.ssl.SslException
import org.opencoap.ssl.transport.ByteBufferPacket
import org.opencoap.ssl.transport.DtlsServer
import org.opencoap.ssl.transport.DtlsSessionLifecycleCallbacks
import org.opencoap.ssl.transport.NoOpsSessionStore
import org.opencoap.ssl.transport.SessionStore
import java.nio.ByteBuffer
import java.time.Duration
import java.util.concurrent.CompletableFuture
import java.util.concurrent.CompletableFuture.completedFuture

class DtlsChannelHandler @JvmOverloads constructor(
    private val sslConfig: SslConfig,
    private val expireAfter: Duration = Duration.ofSeconds(60),
    private val sessionStore: SessionStore = NoOpsSessionStore,
    private val lifecycleCallbacks: DtlsSessionLifecycleCallbacks = object : DtlsSessionLifecycleCallbacks {}
) : ChannelDuplexHandler() {
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
        this.dtlsServer = DtlsServer(::write, sslConfig, expireAfter, sessionStore::write, lifecycleCallbacks, ctx.executor())
    }

    override fun channelRead(ctx: ChannelHandlerContext, msg: Any) {
        if (msg !is DatagramPacket) {
            ctx.fireChannelRead(msg)
            return
        }

        msg.useAndRelease {
            val buffer = ctx.alloc().buffer(msg.content().readableBytes())
            buffer.useAndRelease { contentBuffer ->

                val result = contentBuffer.writeThroughNioBuffer { buf ->
                    dtlsServer.handleReceived(msg.sender(), msg.content().nioBuffer()) { buf }
                }

                when (result) {
                    is DtlsServer.ReceiveResult.Handled -> Unit // do nothing
                    is DtlsServer.ReceiveResult.DecryptFailed -> Unit // do nothing

                    is DtlsServer.ReceiveResult.Decrypted -> {
                        val datagramPacket = DatagramPacketWithContext(contentBuffer.retain(), null, result.packet.peerAddress, result.packet.sessionContext)
                        ctx.fireChannelRead(datagramPacket)
                    }

                    is DtlsServer.ReceiveResult.CidSessionMissing -> loadSession(result, msg.retain(), ctx)
                }
            }
        }
    }

    private fun loadSession(result: DtlsServer.ReceiveResult.CidSessionMissing, msg: DatagramPacket, ctx: ChannelHandlerContext) {
        sessionStore.read(result.cid)
            .thenApplyAsync({ sessBuf -> dtlsServer.loadSession(sessBuf, msg.sender(), result.cid) }, ctx.executor())
            .whenComplete { isLoaded: Boolean?, _ ->
                if (isLoaded == true) {
                    channelRead(ctx, msg)
                } else {
                    msg.release()
                }
            }
    }

    override fun write(ctx: ChannelHandlerContext, msg: Any, promise: ChannelPromise) {
        when (msg) {
            is DatagramPacket -> write(msg, promise, ctx)
            is SessionAuthenticationContext -> {
                msg.map.forEach { (key, value) ->
                    if (!dtlsServer.putSessionAuthenticationContext(msg.adr, key, value)) {
                        promise.setFailure(SslException("Session does not exists"))
                    }
                }
                if (!promise.isDone) {
                    promise.setSuccess()
                }
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
