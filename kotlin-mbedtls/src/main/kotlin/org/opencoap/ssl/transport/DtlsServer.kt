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
import org.opencoap.ssl.SslException
import org.opencoap.ssl.SslHandshakeContext
import org.opencoap.ssl.SslSession
import org.slf4j.LoggerFactory
import java.net.InetSocketAddress
import java.nio.ByteBuffer
import java.nio.channels.DatagramChannel
import java.util.concurrent.CompletableFuture
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicInteger

/*
Single threaded dtls server on top of DatagramChannel.
 */
class DtlsServer(
    private val channel: DatagramChannel,
    private val sslConfig: SslConfig,
    private val executor: ExecutorService = Executors.newSingleThreadExecutor { Thread(it, "dtls-srv-" + threadIndex.getAndIncrement()) }
) {

    companion object {
        private val threadIndex = AtomicInteger(0)

        fun create(config: SslConfig, listenPort: Int = 0): DtlsServer {
            val channel = DatagramChannel.open().bind(InetSocketAddress("0.0.0.0", listenPort))
            return DtlsServer(channel, config)
        }
    }

    private val logger = LoggerFactory.getLogger(javaClass)

    // note: must be used only from executor
    private val sessions = HashMap<InetSocketAddress, SslContext>()

    fun listen(handler: (InetSocketAddress, ByteArray) -> Unit): DtlsServer {
        channel.listen { adr: InetSocketAddress, buf: ByteBuffer ->
            // need to handle incoming message in executor for thread safety
            executor.submit { onReceived(adr, buf, wrap(handler)) }.get()
        }
        return this
    }

    fun send(data: ByteArray, target: InetSocketAddress): CompletableFuture<Boolean> = executor.supply {
        val sslSession = sessions[target]
        if (sslSession != null && sslSession is SslSession) {
            val encBuffer = sslSession.encrypt(data)
            channel.send(encBuffer, target)
            true
        } else {
            false
        }
    }

    private fun onReceived(peerAddress: InetSocketAddress, buffer: ByteBuffer, handler: (InetSocketAddress, ByteArray) -> Unit) {
        try {
            when (val ctx = sessions[peerAddress]) {
                is SslSession ->
                    handler.invoke(peerAddress, ctx.decrypt(buffer))

                is SslHandshakeContext ->
                    sessions[peerAddress] = ctx.step(buffer) { channel.send(it, peerAddress) }

                null -> {
                    sessions[peerAddress] = sslConfig.newContext()
                    onReceived(peerAddress, buffer, handler)
                }
            }
        } catch (ex: SslException) {
            logger.warn("[{}] DTLS failed: {}", peerAddress, ex.message)
            sessions.remove(peerAddress)
        } catch (ex: Exception) {
            logger.error(ex.toString(), ex)
            sessions.remove(peerAddress)
        }
    }

    private fun wrap(underlying: (InetSocketAddress, ByteArray) -> Unit) =
        { adr: InetSocketAddress, packet: ByteArray ->
            try {
                underlying.invoke(adr, packet)
            } catch (ex: Exception) {
                logger.error(ex.toString(), ex)
            }
        }

    fun close() {
        channel.close()
        executor.shutdown()
    }

    fun numberOfSessions() = sessions.size
    fun localPort() = (channel.localAddress as InetSocketAddress).port
}
