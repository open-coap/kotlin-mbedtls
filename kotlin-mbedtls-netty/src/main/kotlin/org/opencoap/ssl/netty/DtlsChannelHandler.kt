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

import io.netty.channel.ChannelDuplexHandler
import io.netty.channel.ChannelHandlerContext
import io.netty.channel.ChannelPromise
import io.netty.channel.socket.DatagramPacket
import org.opencoap.ssl.SslConfig
import org.opencoap.ssl.transport.ByteBufferPacket
import org.opencoap.ssl.transport.DrainingSessionStore
import org.opencoap.ssl.transport.DtlsServer
import org.opencoap.ssl.transport.DtlsSessionLifecycleCallbacks
import org.opencoap.ssl.transport.NoOpsSessionStore
import org.opencoap.ssl.transport.SessionStore
import org.slf4j.LoggerFactory
import java.nio.ByteBuffer
import java.time.Duration
import java.util.concurrent.CompletableFuture
import java.util.concurrent.CompletableFuture.completedFuture
import java.util.concurrent.TimeUnit

class DtlsChannelHandler @JvmOverloads constructor(
    private val sslConfig: SslConfig,
    private val expireAfter: Duration = Duration.ofSeconds(60),
    sessionStore: SessionStore = NoOpsSessionStore,
    private val lifecycleCallbacks: DtlsSessionLifecycleCallbacks = object : DtlsSessionLifecycleCallbacks {},
    private val cidRequired: Boolean = false,
    // how long close() waits for in-flight session store reads, so that the sessions they read get stored again
    private val pendingSessionLoadsTimeout: Duration = Duration.ofSeconds(5)
) : ChannelDuplexHandler() {
    private val logger = LoggerFactory.getLogger(javaClass)
    private val drainingSessionStore = DrainingSessionStore(sessionStore)
    private lateinit var ctx: ChannelHandlerContext
    lateinit var dtlsServer: DtlsServer

    // completes on ctx.executor() once sessions are closed, accessed only from ctx.executor()
    private var sessionsClosed: CompletableFuture<Unit>? = null

    private fun write(packet: ByteBufferPacket): CompletableFuture<Boolean> {
        val dtlsPacket = DatagramPacket(packet.buffer.toByteBuf(), packet.peerAddress)

        if (!ctx.channel().isWritable) {
            return completedFuture(false)
        }
        return ctx.writeAndFlush(dtlsPacket).toCompletableFuture()
    }

    override fun handlerAdded(ctx: ChannelHandlerContext) {
        this.ctx = ctx
        this.dtlsServer = DtlsServer(::write, sslConfig, expireAfter, drainingSessionStore::write, lifecycleCallbacks, ctx.executor(), cidRequired)
    }

    override fun close(ctx: ChannelHandlerContext, promise: ChannelPromise) {
        // a second close() waits for the first one to close sessions
        val sessionsClosed = this.sessionsClosed ?: closeSessionsWhenDrained(ctx).also { this.sessionsClosed = it }
        sessionsClosed.whenComplete { _, _ -> ctx.close(promise) }
    }

    private fun closeSessionsWhenDrained(ctx: ChannelHandlerContext): CompletableFuture<Unit> {
        val sessionsClosed = CompletableFuture<Unit>()
        val timeout = ctx.executor().schedule(Runnable { closeSessions(sessionsClosed, timedOut = true) }, pendingSessionLoadsTimeout.toMillis(), TimeUnit.MILLISECONDS)

        // a session store read in flight may already have removed a session from the store, wait until it is loaded or
        // stored back; always continue on the executor, so that the loads scheduled by reads run first
        drainingSessionStore.close().whenComplete { _, _ ->
            ctx.executor().execute {
                timeout.cancel(false)
                closeSessions(sessionsClosed, timedOut = false)
            }
        }
        return sessionsClosed
    }

    private fun closeSessions(sessionsClosed: CompletableFuture<Unit>, timedOut: Boolean) {
        if (sessionsClosed.isDone) return
        if (timedOut) logger.warn("Closing with session store read(s) still pending after {}", pendingSessionLoadsTimeout)
        dtlsServer.close()
        sessionsClosed.complete(Unit)
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

                is DtlsServer.ReceiveResult.CidSessionMissing -> loadSession(result, msg.retain(), ctx)
            }
        }
    }

    private fun loadSession(result: DtlsServer.ReceiveResult.CidSessionMissing, msg: DatagramPacket, ctx: ChannelHandlerContext) {
        drainingSessionStore.read(result.cid)
            .thenApplyAsync({ sessBuf -> dtlsServer.loadSession(sessBuf, msg.sender(), result.cid, msg.content().nioBuffer()) }, ctx.executor())
            .whenComplete { loadResult: DtlsServer.SessionLoadResult?, _ ->
                when (loadResult) {
                    is DtlsServer.SessionLoadResult.Loaded -> channelRead(ctx, msg)

                    is DtlsServer.SessionLoadResult.NotFound -> msg.release()

                    is DtlsServer.SessionLoadResult.RecordVerificationFailed -> msg.release()

                    is DtlsServer.SessionLoadResult.NotReadable -> msg.release()

                    is DtlsServer.SessionLoadResult.ServerClosed -> msg.release()

                    // the session store read itself failed
                    null -> msg.release()
                }
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
