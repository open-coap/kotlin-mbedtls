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

import org.opencoap.ssl.HelloVerifyRequired
import org.opencoap.ssl.SslConfig
import org.opencoap.ssl.SslHandshakeContext
import org.opencoap.ssl.SslSession
import org.opencoap.ssl.transport.Packet.Companion.EMPTY_BYTEBUFFER
import java.net.InetAddress
import java.net.InetSocketAddress
import java.nio.ByteBuffer
import java.time.Duration
import java.util.concurrent.CompletableFuture
import java.util.concurrent.CompletableFuture.completedFuture
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicInteger

/*
Single DTLS connection, transmitter. Can be server or client mode.
 */
class DtlsTransmitter private constructor(
    val remoteAddress: InetSocketAddress,
    internal val transport: Transport<ByteBuffer>,
    private val sslSession: SslSession,
    private val executor: ExecutorService,
) : Transport<ByteBuffer> {

    override fun send(packet: ByteBuffer): CompletableFuture<Boolean> {
        return executor
            .supply { sslSession.encrypt(packet) }
            .thenCompose(transport::send)
    }

    fun send(text: String) = send(text.toByteBuffer())

    override fun receive(timeout: Duration): CompletableFuture<ByteBuffer> {
        return transport.receive(timeout).thenApplyAsync({
            if (it.remaining() == 0) EMPTY_BYTEBUFFER else sslSession.decrypt(it)
        }, executor)
    }

    fun receive() = receive(Duration.ofSeconds(30))

    override fun localPort() = transport.localPort()

    override fun close() {
        transport.close()
        executor.supply(sslSession::close).join()
    }

    fun closeNotify() {
        executor.supply {
            transport.send(sslSession.closeNotify())
        }.join()
        close()
    }

    val cipherSuite: String get() = sslSession.cipherSuite
    val peerCid: ByteArray? get() = sslSession.peerCid
    val ownCid: ByteArray? get() = sslSession.ownCid
    val peerCertificateSubject: String? get() = sslSession.peerCertificateSubject

    fun saveSession() = sslSession.saveAndClose()

    fun storeOnClose(store: (ByteArray) -> Unit): Transport<ByteBuffer> = object : Transport<ByteBuffer> by this {
        override fun close() {
            transport.close()
            executor.supply {
                store(sslSession.saveAndClose())
            }.join()
        }
    }

    companion object {
        private val threadIndex = AtomicInteger(0)
        internal fun newSingleExecutor(): ExecutorService {
            return Executors.newSingleThreadExecutor { Thread(it, "dtls-" + threadIndex.getAndIncrement()) }
        }

        @JvmStatic
        @JvmOverloads
        fun connect(server: Transport<*>, conf: SslConfig, bindPort: Int = 0): CompletableFuture<DtlsTransmitter> {
            return connect(InetSocketAddress(InetAddress.getLocalHost(), server.localPort()), conf, bindPort)
        }

        @JvmStatic
        @JvmOverloads
        fun connect(dest: InetSocketAddress, conf: SslConfig, bindPort: Int = 0): CompletableFuture<DtlsTransmitter> {
            return connect(dest, conf, DatagramChannelAdapter.connect(dest, bindPort))
        }

        @JvmStatic
        @JvmOverloads
        fun connect(dest: InetSocketAddress, conf: SslConfig, trans: Transport<ByteBuffer>, executor: ExecutorService = newSingleExecutor()): CompletableFuture<DtlsTransmitter> {
            val promise = CompletableFuture<DtlsTransmitter>()
            val sslHandshakeContext = conf.newContext(dest)
            val send: (ByteBuffer) -> Unit = { trans.send(it) }

            fun handleReceive(buffer: ByteBuffer): CompletableFuture<SslSession> {
                val newSslContext = sslHandshakeContext.step(buffer, send)

                return when (newSslContext) {
                    is SslSession -> completedFuture(newSslContext)
                    is SslHandshakeContext -> {
                        val timeout = if (newSslContext.readTimeout.isZero) Duration.ofSeconds(1) else newSslContext.readTimeout
                        trans.receive(timeout).thenComposeAsync(::handleReceive, executor)
                    }
                }
            }

            val sslContext: SslHandshakeContext = sslHandshakeContext.step(send) as SslHandshakeContext
            trans.receive(sslContext.readTimeout)
                .thenComposeAsync(::handleReceive, executor)
                .whenComplete { sslSession, ex ->
                    when (ex?.cause) {
                        null -> promise.complete(DtlsTransmitter(dest, trans, sslSession, executor))

                        is HelloVerifyRequired -> {
                            sslHandshakeContext.close()
                            connect(dest, conf, trans, executor).whenComplete { t, ex2 ->
                                if (ex2 != null) {
                                    promise.completeExceptionally(ex2)
                                } else {
                                    promise.complete(t)
                                }
                            }
                        }

                        else -> {
                            sslHandshakeContext.close()
                            trans.close()
                            promise.completeExceptionally(ex)
                        }
                    }
                }

            return promise
        }

        @JvmStatic
        @JvmOverloads
        fun create(dest: InetSocketAddress, sslSession: SslSession, bindPort: Int = 0): DtlsTransmitter {
            return create(dest, sslSession, DatagramChannelAdapter.connect(dest, bindPort))
        }

        @JvmStatic
        @JvmOverloads
        fun create(dest: InetSocketAddress, sslSession: SslSession, cnnTransmitter: Transport<ByteBuffer>): DtlsTransmitter {
            return DtlsTransmitter(dest, cnnTransmitter, sslSession, newSingleExecutor())
        }
    }
}
