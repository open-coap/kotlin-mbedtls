/*
 * Copyright (c) 2022-2026 kotlin-mbedtls contributors (https://github.com/open-coap/kotlin-mbedtls)
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

import io.netty.buffer.ByteBufUtil
import io.netty.channel.ChannelDuplexHandler
import io.netty.channel.ChannelHandlerContext
import io.netty.channel.ChannelPromise
import io.netty.channel.socket.DatagramPacket
import org.opencoap.ssl.SslConfig
import org.opencoap.ssl.transport.ByteBufferPacket
import org.opencoap.ssl.transport.DtlsServer
import org.opencoap.ssl.transport.DtlsSessionLifecycleCallbacks
import org.opencoap.ssl.transport.NoOpsSessionStore
import org.opencoap.ssl.transport.SessionStore
import org.opencoap.ssl.transport.SessionWithContext
import org.slf4j.LoggerFactory
import java.nio.ByteBuffer
import java.time.Duration
import java.util.concurrent.CompletableFuture
import java.util.concurrent.CompletableFuture.completedFuture
import java.util.concurrent.Future
import java.util.concurrent.RejectedExecutionException
import java.util.concurrent.TimeUnit

class DtlsChannelHandler @JvmOverloads constructor(
    private val sslConfig: SslConfig,
    private val expireAfter: Duration = Duration.ofSeconds(60),
    private val sessionStore: SessionStore = NoOpsSessionStore,
    private val lifecycleCallbacks: DtlsSessionLifecycleCallbacks = object : DtlsSessionLifecycleCallbacks {},
    private val cidRequired: Boolean = false,
    // how long close() waits for in-flight session store reads, so that the sessions they load get stored again
    private val pendingSessionLoadsTimeout: Duration = Duration.ofSeconds(5)
) : ChannelDuplexHandler() {
    private val logger = LoggerFactory.getLogger(javaClass)
    private lateinit var ctx: ChannelHandlerContext
    lateinit var dtlsServer: DtlsServer

    // state below is accessed only from ctx.executor()
    private var pendingSessionLoads = 0
    private var closing = false
    private var closed = false
    private var pendingClose: ChannelPromise? = null
    private var pendingCloseTimeout: Future<*>? = null

    private fun write(packet: ByteBufferPacket): CompletableFuture<Boolean> {
        val dtlsPacket = DatagramPacket(packet.buffer.toByteBuf(), packet.peerAddress)

        if (!ctx.channel().isWritable) {
            return completedFuture(false)
        }
        return ctx.writeAndFlush(dtlsPacket).toCompletableFuture()
    }

    override fun handlerAdded(ctx: ChannelHandlerContext) {
        this.ctx = ctx
        this.dtlsServer = DtlsServer(::write, sslConfig, expireAfter, sessionStore::write, lifecycleCallbacks, ctx.executor(), cidRequired)
    }

    override fun close(ctx: ChannelHandlerContext, promise: ChannelPromise) {
        pendingClose?.let { firstClose ->
            firstClose.addListener { ctx.close(promise) }
            return
        }

        closing = true
        if (pendingSessionLoads == 0) {
            closeNow(ctx, promise)
            return
        }

        // a session store read may already have removed a session from the store, wait for it to be loaded
        // so that closeSessions() stores it again before the channel is closed
        pendingClose = promise
        pendingCloseTimeout = ctx.executor().schedule(::completePendingClose, pendingSessionLoadsTimeout.toMillis(), TimeUnit.MILLISECONDS)
    }

    private fun completePendingClose() {
        val promise = pendingClose ?: return
        pendingClose = null
        pendingCloseTimeout?.cancel(false)
        if (pendingSessionLoads > 0) {
            logger.warn("Closing with {} session load(s) still pending after {}", pendingSessionLoads, pendingSessionLoadsTimeout)
        }
        closeNow(ctx, promise)
    }

    private fun closeNow(ctx: ChannelHandlerContext, promise: ChannelPromise) {
        closed = true
        dtlsServer.closeSessions()
        ctx.close(promise)
    }

    override fun channelRead(ctx: ChannelHandlerContext, msg: Any) {
        if (msg !is DatagramPacket) {
            ctx.fireChannelRead(msg)
            return
        }

        msg.useAndRelease {
            val result = dtlsServer.handleReceived(msg.sender(), msg.content().nioBuffer())

            when (result) {
                // do nothing
                is DtlsServer.ReceiveResult.Handled -> Unit

                // do nothing
                is DtlsServer.ReceiveResult.DecryptFailed -> Unit

                is DtlsServer.ReceiveResult.Decrypted -> ctx.fireChannelRead(DatagramPacketWithContext.from(result.packet))

                is DtlsServer.ReceiveResult.CidSessionMissing ->
                    if (closing) {
                        // reading would remove the session from the store, leave it there for another server
                        logger.info("[{}] [CID:{}] DTLS session not loaded, closing", msg.sender(), ByteBufUtil.hexDump(result.cid))
                        lifecycleCallbacks.messageDropped(msg.sender())
                    } else {
                        loadSession(result, msg.retain(), ctx)
                    }
            }
        }
    }

    private fun loadSession(result: DtlsServer.ReceiveResult.CidSessionMissing, msg: DatagramPacket, ctx: ChannelHandlerContext) {
        pendingSessionLoads++
        sessionStore.read(result.cid).whenComplete { sessBuf: SessionWithContext?, readError: Throwable? ->
            // the read may complete on any thread, also exceptionally, so always continue on the channel's executor
            try {
                ctx.executor().execute { onSessionRead(sessBuf, readError, result.cid, msg, ctx) }
            } catch (_: RejectedExecutionException) {
                msg.release()
            }
        }
    }

    private fun onSessionRead(sessBuf: SessionWithContext?, readError: Throwable?, cid: ByteArray, msg: DatagramPacket, ctx: ChannelHandlerContext) {
        pendingSessionLoads--
        try {
            val loadResult = when {
                // the session store read itself failed
                readError != null -> null

                // gave up waiting in close(), sessions are no longer stored
                closed -> {
                    if (sessBuf != null) logger.warn("[{}] [CID:{}] DTLS session read after close, dropped", msg.sender(), ByteBufUtil.hexDump(cid))
                    null
                }

                else -> dtlsServer.loadSession(sessBuf, msg.sender(), cid, msg.content().nioBuffer())
            }

            // while closing, a loaded session is kept only for closeSessions() to store it, the packet is dropped
            if (loadResult is DtlsServer.SessionLoadResult.Loaded && !closing) {
                channelRead(ctx, msg)
            } else {
                msg.release()
            }
        } finally {
            if (closing && pendingSessionLoads == 0) completePendingClose()
        }
    }

    override fun write(ctx: ChannelHandlerContext, msg: Any, promise: ChannelPromise) {
        when (msg) {
            is DatagramPacketWithContext -> {
                write(msg, promise, ctx)
                dtlsServer.handleOutboundDtlsSessionContext(msg.recipient(), msg.sessionContext, promise.toCompletableFuture())
            }

            is DatagramPacket -> write(msg, promise, ctx)

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
