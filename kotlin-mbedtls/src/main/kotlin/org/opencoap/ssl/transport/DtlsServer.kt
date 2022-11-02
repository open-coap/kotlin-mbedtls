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

package org.opencoap.ssl.transport

import org.opencoap.ssl.CloseNotifyException
import org.opencoap.ssl.HelloVerifyRequired
import org.opencoap.ssl.SslConfig
import org.opencoap.ssl.SslContext
import org.opencoap.ssl.SslException
import org.opencoap.ssl.SslHandshakeContext
import org.opencoap.ssl.SslSession
import org.slf4j.LoggerFactory
import java.net.InetSocketAddress
import java.nio.ByteBuffer
import java.time.Duration
import java.util.concurrent.CompletableFuture
import java.util.concurrent.CompletableFuture.completedFuture
import java.util.concurrent.ScheduledFuture
import java.util.concurrent.ScheduledThreadPoolExecutor
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger

/*
Single threaded dtls server on top of DatagramChannel.
 */
class DtlsServer private constructor(
    private val transport: Transport<ByteBufferPacket>,
    private val sslConfig: SslConfig,
    private val expireAfter: Duration,
    private val sessionStore: SessionStore,
) : Transport<BytesPacket> {

    companion object {
        private val EMPTY_BUFFER = ByteBuffer.allocate(0)

        private val threadIndex = AtomicInteger(0)

        @JvmStatic
        @JvmOverloads
        fun create(
            config: SslConfig,
            listenPort: Int = 0,
            expireAfter: Duration = Duration.ofSeconds(60),
            sessionStore: SessionStore = NoOpsSessionStore
        ): DtlsServer {
            val channel = DatagramChannelAdapter.open(listenPort)
            return DtlsServer(channel, config, expireAfter, sessionStore)
        }
    }

    private val logger = LoggerFactory.getLogger(javaClass)
    val executor = ScheduledThreadPoolExecutor(1) { r: Runnable -> Thread(r, "dtls-srv-" + threadIndex.getAndIncrement()) }

    // note: must be used only from executor
    private val sessions = mutableMapOf<InetSocketAddress, DtlsState>()
    private val cidSize = sslConfig.cidSupplier.next().size

    override fun receive(timeout: Duration): CompletableFuture<BytesPacket> {
        return transport.receive(timeout).thenComposeAsync({ packet ->
            if (packet == Packet.EmptyByteBufferPacket) return@thenComposeAsync completedFuture(Packet.EmptyBytesPacket)

            val adr: InetSocketAddress = packet.peerAddress
            val buf: ByteBuffer = packet.buffer

            handleReceived(adr, buf, timeout)
        }, executor)
    }

    private fun handleReceived(adr: InetSocketAddress, buf: ByteBuffer, timeout: Duration): CompletableFuture<BytesPacket> {
        val cid by lazy { SslContext.peekCID(cidSize, buf) }
        val dtlsState = sessions[adr]

        return when {
            dtlsState is DtlsHandshake -> {
                dtlsState.step(buf)
                receive(timeout)
            }

            dtlsState is DtlsSession -> {
                val plainBytes = dtlsState.decrypt(buf)
                if (plainBytes.isNotEmpty())
                    completedFuture(Packet(plainBytes, adr))
                else
                    receive(timeout)
            }

            // no session, but dtls packet contains CID
            cid != null -> {
                val copyBuf = buf.copyDirect()
                @Suppress("UnsafeCallOnNullableType") // smart casting does not work for lazy delegate
                loadSession(cid!!, adr).thenCompose { isLoaded ->
                    if (isLoaded) {
                        handleReceived(adr, copyBuf, timeout)
                    } else {
                        receive(timeout)
                    }
                }
            }

            // new handshake
            else -> {
                sessions[adr] = DtlsHandshake(sslConfig.newContext(adr), adr)
                handleReceived(adr, buf, timeout)
            }
        }
    }

    override fun send(packet: Packet<ByteArray>): CompletableFuture<Boolean> = executor.supply {
        when (val dtlsState = sessions[packet.peerAddress]) {
            is DtlsSession -> {
                transport.send(packet.map(dtlsState::encrypt))
                true
            }

            else -> false
        }
    }

    fun numberOfSessions(): Int = executor.supply { sessions.size }.join()

    override fun localPort() = transport.localPort()

    override fun close() {
        executor.supply {
            transport.close()

            val iterator = sessions.iterator()
            while (iterator.hasNext()) {
                val dtlsState = iterator.next().value
                iterator.remove()
                dtlsState.storeAndClose()
            }
        }.get(30, TimeUnit.SECONDS)
        executor.shutdown()
    }

    private fun loadSession(cid: ByteArray, adr: InetSocketAddress): CompletableFuture<Boolean> {
        return sessionStore.read(cid)
            .thenApplyAsync({ sessBuf ->
                try {
                    if (sessBuf == null) {
                        logger.warn("[{}] [CID:{}] DTLS session not found", adr, cid.toHex())
                        false
                    } else {
                        sessions[adr] = DtlsSession(sslConfig.loadSession(cid, sessBuf, adr), adr)
                        true
                    }
                } catch (ex: SslException) {
                    logger.warn("[{}] [CID:{}] Failed to load session: {}", adr, cid.toHex(), ex.message)
                    false
                }
            }, executor)
    }

    private fun DtlsState.closeAndRemove() {
        sessions.remove(this.peerAddress, this)
    }

    private sealed class DtlsState(val peerAddress: InetSocketAddress) {
        protected var scheduledTask: ScheduledFuture<*>? = null

        abstract fun storeAndClose()
    }

    private inner class DtlsHandshake(
        private val ctx: SslHandshakeContext,
        peerAddress: InetSocketAddress
    ) : DtlsState(peerAddress) {

        private fun send(buf: ByteBuffer) {
            transport.send(Packet(buf, peerAddress))
        }

        private fun retryStep() = step(EMPTY_BUFFER)

        fun step(encPacket: ByteBuffer) {
            scheduledTask?.cancel(false)

            try {
                when (val newCtx = ctx.step(encPacket, ::send)) {
                    is SslHandshakeContext -> {
                        scheduledTask = if (!newCtx.readTimeout.isZero) {
                            executor.schedule(::retryStep, newCtx.readTimeout)
                        } else {
                            executor.schedule(::timeout, expireAfter)
                        }
                    }

                    is SslSession ->
                        sessions[peerAddress] = DtlsSession(newCtx, peerAddress)
                }
            } catch (ex: HelloVerifyRequired) {
                closeAndRemove()
            } catch (ex: SslException) {
                logger.warn("[{}] DTLS failed: {}", peerAddress, ex.message)
                closeAndRemove()
            } catch (ex: Exception) {
                logger.error(ex.toString(), ex)
                closeAndRemove()
            }
        }

        fun timeout() {
            closeAndRemove()
            logger.warn("[{}] DTLS handshake expired", peerAddress)
        }

        override fun storeAndClose() {
            ctx.close()
        }
    }

    private inner class DtlsSession(
        private val ctx: SslSession,
        peerAddress: InetSocketAddress
    ) : DtlsState(peerAddress) {

        override fun storeAndClose() {
            if (ctx.ownCid != null) {
                try {
                    sessionStore.write(ctx.ownCid, ctx.saveAndClose())
                } catch (ex: SslException) {
                    logger.warn("[{}] DTLS failed to store session: {}", peerAddress, ex.message)
                }
            } else {
                ctx.close()
            }
        }

        fun decrypt(encPacket: ByteBuffer): ByteArray {
            scheduledTask?.cancel(false)
            try {
                val plainBuf = ctx.decrypt(encPacket)
                scheduledTask = executor.schedule(::timeout, expireAfter)
                return plainBuf
            } catch (ex: CloseNotifyException) {
                logger.info("[{}] DTLS received close notify", peerAddress)
            } catch (ex: SslException) {
                logger.warn("[{}] DTLS failed: {}", peerAddress, ex.message)
            }
            closeAndRemove()
            return byteArrayOf()
        }

        fun encrypt(plainPacket: ByteArray): ByteBuffer {
            try {
                return ctx.encrypt(plainPacket)
            } catch (ex: SslException) {
                logger.warn("[{}] DTLS failed: {}", peerAddress, ex.message)
                closeAndRemove()
                throw ex
            }
        }

        fun timeout() {
            sessions.remove(peerAddress, this)
            logger.info("[{}] DTLS connection expired", peerAddress)
            storeAndClose()
        }
    }
}
