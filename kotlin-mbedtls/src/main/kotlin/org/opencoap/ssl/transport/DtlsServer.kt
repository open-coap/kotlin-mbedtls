/*
 * Copyright (c) 2022 kotlin-mbedtls contributors (https://github.com/open-coap/kotlin-mbedtls)
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
import java.nio.channels.DatagramChannel
import java.time.Duration
import java.util.concurrent.ArrayBlockingQueue
import java.util.concurrent.BlockingQueue
import java.util.concurrent.CompletableFuture
import java.util.concurrent.CompletionStage
import java.util.concurrent.ScheduledThreadPoolExecutor
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger

/*
Single threaded dtls server on top of DatagramChannel.
 */
class DtlsServer private constructor(
    private val channel: DatagramChannel,
    private val sslConfig: SslConfig,
    private val expireAfter: Duration,
    private val sessionStore: SessionStore,
) {

    companion object {
        private val threadIndex = AtomicInteger(0)

        @JvmStatic
        @JvmOverloads
        fun create(
            config: SslConfig,
            listenPort: Int = 0,
            expireAfter: Duration = Duration.ofSeconds(60),
            sessionStore: SessionStore = NoOpsSessionStore
        ): DtlsServer {
            val channel = DatagramChannel.open().bind(InetSocketAddress("0.0.0.0", listenPort))
            return DtlsServer(channel, config, expireAfter, sessionStore)
        }
    }

    private val logger = LoggerFactory.getLogger(javaClass)
    val executor = ScheduledThreadPoolExecutor(1) { r: Runnable -> Thread(r, "dtls-srv-" + threadIndex.getAndIncrement()) }

    // note: must be used only from executor
    private val localActionPromises = ThreadLocal<MutableMap<InetSocketAddress, CompletableFuture<Action>>>()
    private val actionPromises: MutableMap<InetSocketAddress, CompletableFuture<Action>>
        get() = localActionPromises.get()
    private val cidSize = sslConfig.cidSupplier.next().size

    init {
        executor.execute { localActionPromises.set(hashMapOf()) }
    }

    fun listen(handler: Handler): DtlsServer {
        val bufPool: BlockingQueue<ByteBuffer> = ArrayBlockingQueue(1)
        bufPool.put(ByteBuffer.allocateDirect(16384))

        val nonThrowingHandler = handler.decorateWithCatcher()
        channel.listen(bufPool) { adr: InetSocketAddress, buf: ByteBuffer ->
            // need to handle incoming message in executor for thread safety
            executor.execute {
                val promise = actionPromises.remove(adr)
                if (promise != null) {
                    promise.complete(DecryptAction(buf))
                } else {
                    val cid = SslContext.peekCID(cidSize, buf)
                    if (cid != null) {
                        loadSession(buf.copyDirect(), cid, adr, handler)
                    } else {
                        DtlsHandshake(sslConfig.newContext(adr), adr, nonThrowingHandler)
                            .invoke(DecryptAction(buf))
                    }
                }

                bufPool.put(buf) // return buffer to the pool
            }
        }
        return this
    }

    fun send(data: ByteArray, target: InetSocketAddress): CompletableFuture<Boolean> = executor.supply {
        val promise = actionPromises.remove(target)
        promise?.complete(EncryptAction(data)) ?: false
    }

    fun numberOfSessions(): Int = executor.supply { actionPromises.size }.join()
    val localAddress: InetSocketAddress
        get() = channel.localAddress as InetSocketAddress

    fun localPort() = localAddress.port

    fun close() {
        executor.supply {
            channel.close()
            val iterator = actionPromises.iterator()
            while (iterator.hasNext()) {
                val promise = iterator.next().value
                iterator.remove()
                promise.complete(CloseAction)
            }
        }.get(30, TimeUnit.SECONDS)
        executor.shutdown()
    }

    private fun receive(peerAddress: InetSocketAddress, timeout: Duration = expireAfter, timeoutAction: Action = TimeoutAction): CompletionStage<Action> {
        val timeoutMillis = if (timeout.isZero) expireAfter.toMillis() else timeout.toMillis()

        val promise = CompletableFuture<Action>()
        val scheduledFuture = executor.schedule({ promise.complete(timeoutAction) }, timeoutMillis, TimeUnit.MILLISECONDS)
        actionPromises.put(peerAddress, promise)?.cancel(false)

        promise.thenRun {
            scheduledFuture.cancel(true)
            actionPromises.remove(peerAddress, promise)
        }
        return promise
    }

    private fun loadSession(encBuf: ByteBuffer, cid: ByteArray, adr: InetSocketAddress, handler: Handler) {
        sessionStore.read(cid)
            .thenAcceptAsync({ sessBuf ->
                if (sessBuf == null) {
                    logger.warn("[{}] [CID:{}] DTLS session not found", adr, cid.toHex())
                } else {
                    DtlsSession(sslConfig.loadSession(cid, sessBuf, adr), adr, handler)
                        .invoke(DecryptAction(encBuf))
                }
            }, executor)
            .whenComplete { _, ex ->
                when (ex) {
                    null -> Unit // no error
                    is SslException -> logger.warn("[{}] [CID:{}] Failed to load session: {}", adr, cid.toHex(), ex.message)
                    else -> logger.error(ex.message, ex)
                }
            }
    }

    private fun Handler.decorateWithCatcher(): Handler {
        return object : Handler {
            override fun invoke(adr: InetSocketAddress, packet: ByteArray) {
                try {
                    this@decorateWithCatcher(adr, packet)
                } catch (ex: Exception) {
                    logger.error(ex.toString(), ex)
                }
            }
        }
    }

    private inner class DtlsHandshake(private val ctx: SslHandshakeContext, private val peerAddress: InetSocketAddress, private val handler: Handler) {
        private fun send(buf: ByteBuffer) {
            channel.send(buf, peerAddress)
        }

        operator fun invoke(action: Action?, err: Throwable? = null) {
            try {
                when (action) {
                    is DecryptAction -> stepHandshake(action.encPacket)
                    is EncryptAction -> return
                    is CloseAction -> ctx.close()
                    is TimeoutAction -> {
                        logger.warn("[{}] DTLS handshake expired", peerAddress)
                        ctx.close()
                    }
                    null -> throw err!!
                }
            } catch (ex: HelloVerifyRequired) {
                ctx.close()
            } catch (ex: SslException) {
                logger.warn("[{}] DTLS failed: {}", peerAddress, ex.message)
                ctx.close()
            } catch (ex: Exception) {
                logger.error(ex.toString(), ex)
                ctx.close()
            }
        }

        private fun stepHandshake(encPacket: ByteBuffer) {
            when (val newCtx = ctx.step(encPacket, ::send)) {
                is SslHandshakeContext -> {
                    if (!newCtx.readTimeout.isZero)
                        receive(peerAddress, newCtx.readTimeout, EmptyDecryptAction).whenComplete(::invoke)
                    else
                        receive(peerAddress).whenComplete(::invoke)
                }

                is SslSession -> {
                    val dtlsSession = DtlsSession(newCtx, peerAddress, handler)
                    receive(peerAddress).whenComplete(dtlsSession::invoke)
                }
            }
        }
    }

    private inner class DtlsSession(private val ctx: SslSession, private val peerAddress: InetSocketAddress, private val handler: Handler) {
        operator fun invoke(action: Action?, err: Throwable? = null) {
            try {
                when (action) {
                    null -> throw err!!
                    is DecryptAction -> decrypt(action.encPacket)
                    is EncryptAction -> encrypt(action.plainPacket)
                    is CloseAction -> {
                        logger.info("[{}] DTLS connection closed", peerAddress)
                        close()
                    }
                    is TimeoutAction -> {
                        logger.info("[{}] DTLS connection expired", peerAddress)
                        close()
                    }
                }
            } catch (ex: CloseNotifyException) {
                logger.info("[{}] DTLS received close notify", peerAddress)
                ctx.close()
            } catch (ex: SslException) {
                logger.warn("[{}] DTLS failed: {}", peerAddress, ex.message)
                ctx.close()
            } catch (ex: Throwable) {
                logger.error(ex.message, ex)
                ctx.close()
            }
        }

        private fun close() {
            if (ctx.ownCid != null) {
                sessionStore.write(ctx.ownCid, ctx.saveAndClose())
            } else {
                ctx.close()
            }
        }

        private fun decrypt(encPacket: ByteBuffer) {
            val plainBuf = ctx.decrypt(encPacket)
            receive(peerAddress).whenComplete(::invoke)
            handler(peerAddress, plainBuf)
        }

        private fun encrypt(plainPacket: ByteArray) {
            val encBuf = ctx.encrypt(plainPacket)
            receive(peerAddress).whenComplete(::invoke)
            channel.send(encBuf, peerAddress)
        }
    }

    private sealed interface Action
    private open class DecryptAction(val encPacket: ByteBuffer) : Action
    private object EmptyDecryptAction : DecryptAction(ByteBuffer.allocate(0))
    private class EncryptAction(val plainPacket: ByteArray) : Action
    private object CloseAction : Action
    private object TimeoutAction : Action
}

interface Handler {
    @Throws(Exception::class)
    operator fun invoke(adr: InetSocketAddress, packet: ByteArray)
}
