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

import org.opencoap.ssl.SslConfig
import org.opencoap.ssl.SslContext
import org.opencoap.ssl.SslHandshakeContext
import org.opencoap.ssl.SslSession
import java.io.Closeable
import java.net.InetAddress
import java.net.InetSocketAddress
import java.nio.ByteBuffer
import java.nio.channels.DatagramChannel
import java.nio.channels.SelectionKey
import java.nio.channels.Selector
import java.time.Duration
import java.util.concurrent.CompletableFuture
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicInteger

/*
DTLS transmitter based on DatagramChannel. Uses blocking calls.
 */
class DtlsTransmitter private constructor(
    internal val cnnTrans: ConnectedDatagramTransmitter,
    private val sslSession: SslSession,
    private val executor: ExecutorService
) : Closeable {
    companion object {
        private val threadIndex = AtomicInteger(0)
        internal fun newSingleExecutor(): ExecutorService {
            return Executors.newSingleThreadExecutor { Thread(it, "dtls-" + threadIndex.getAndIncrement()) }
        }

        fun connect(server: DtlsServer, conf: SslConfig): CompletableFuture<DtlsTransmitter> {
            return connect(InetSocketAddress(InetAddress.getLocalHost(), server.localPort()), conf)
        }

        fun connect(peerCnnTrans: ConnectedDatagramTransmitter, conf: SslConfig, bindPort: Int = 0): CompletableFuture<DtlsTransmitter> {
            return connect(peerCnnTrans.localAddress(), conf, bindPort)
        }

        fun connect(dest: InetSocketAddress, conf: SslConfig, bindPort: Int = 0): CompletableFuture<DtlsTransmitter> {
            return connect(conf, ConnectedDatagramTransmitter.connect(dest, bindPort))
        }

        fun connect(conf: SslConfig, channel: ConnectedDatagramTransmitter, executor: ExecutorService = newSingleExecutor()): CompletableFuture<DtlsTransmitter> {
            return executor.supply {
                try {
                    val sslSession = handshake(conf.newContext(), channel)
                    DtlsTransmitter(channel, sslSession, executor)
                } catch (ex: Exception) {
                    channel.close()
                    throw ex
                }
            }
        }

        private fun handshake(handshakeCtx: SslHandshakeContext, channel: ConnectedDatagramTransmitter): SslSession {
            return handshake(handshakeCtx, channel::send, channel::receive)
        }

        internal fun handshake(handshakeCtx: SslHandshakeContext, send: (ByteBuffer) -> Unit, receive: (ByteBuffer, Duration) -> Unit): SslSession {
            val buffer: ByteBuffer = ByteBuffer.allocateDirect(16384)

            var sslContext: SslContext = handshakeCtx.step(send)
            while (sslContext is SslHandshakeContext) {
                receive(buffer, sslContext.readTimeout)
                sslContext = handshakeCtx.step(buffer, send)
            }
            return sslContext as SslSession
        }

        fun create(dest: InetSocketAddress, sslSession: SslSession, bindPort: Int = 0): DtlsTransmitter {
            return create(sslSession, ConnectedDatagramTransmitter.connect(dest, bindPort))
        }

        fun create(sslSession: SslSession, cnnTransmitter: ConnectedDatagramTransmitter): DtlsTransmitter {
            return DtlsTransmitter(cnnTransmitter, sslSession, newSingleExecutor())
        }
    }

    override fun close() {
        cnnTrans.close()
        executor.supply(sslSession::close).join()
    }

    fun send(data: ByteArray) {
        executor.supply { cnnTrans.send(sslSession.encrypt(data)) }.join()
    }

    fun send(text: String) = send(text.encodeToByteArray())

    fun receive(timeout: Duration = Duration.ofSeconds(30)): ByteArray {
        val buffer: ByteBuffer = ByteBuffer.allocateDirect(16384)

        cnnTrans.receive(buffer, timeout)
        if (!buffer.hasRemaining()) {
            return byteArrayOf()
        }

        return executor.supply { sslSession.decrypt(buffer) }.join()
    }

    fun receiveString(): String = receive().decodeToString()

    fun getCipherSuite() = sslSession.getCipherSuite()
    fun getPeerCid() = sslSession.getPeerCid()
    fun saveSession() = sslSession.saveAndClose()
}

interface ConnectedDatagramTransmitter : Closeable {
    fun send(buf: ByteBuffer)
    fun receive(buf: ByteBuffer, timeout: Duration)
    fun localAddress(): InetSocketAddress

    companion object {
        fun connect(dest: InetSocketAddress, listenPort: Int): ConnectedDatagramTransmitter {
            val channel: DatagramChannel = DatagramChannel.open()
            if (listenPort > 0) channel.bind(InetSocketAddress("0.0.0.0", listenPort))
            channel.connect(dest)
            channel.configureBlocking(false)
            val selector: Selector = Selector.open()
            channel.register(selector, SelectionKey.OP_READ)

            return ConnectedDatagramTransmitterImpl(channel, selector)
        }
    }
}

class ConnectedDatagramTransmitterImpl(
    private val channel: DatagramChannel,
    private val selector: Selector
) : ConnectedDatagramTransmitter {
    init {
        require(channel.isConnected)
    }

    override fun send(buf: ByteBuffer) {
        channel.write(buf)
    }

    override fun receive(buf: ByteBuffer, timeout: Duration) {
        channel.receive(buf, selector, timeout)
    }

    override fun localAddress() = (channel.localAddress as InetSocketAddress)

    override fun close() {
        selector.close()
        channel.close()
    }
}
