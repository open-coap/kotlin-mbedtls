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

package org.opencoap.ssl

import org.slf4j.LoggerFactory
import java.net.InetAddress
import java.net.InetSocketAddress
import java.nio.ByteBuffer
import java.nio.channels.DatagramChannel
import java.util.concurrent.CompletableFuture
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.Executors

/*
Single threaded dtls server that uses blocking DatagramChannel.
 */
class DtlsServer(
    listenPort: Int,
    private val sslConfig: SslConfig,
    private val handler: (InetSocketAddress, ByteArray) -> ByteArray,
) {
    private val logger = LoggerFactory.getLogger(javaClass)
    private val channel: DatagramChannel = DatagramChannel.open().bind(InetSocketAddress(InetAddress.getLocalHost(), listenPort))
    private val readPromises = ConcurrentHashMap<InetSocketAddress, CompletableFuture<ByteBuffer>>()

    private val executor = Executors.newSingleThreadExecutor()

    fun start(): DtlsServer {
        executor.execute(this::run);
        return this;
    }

    fun stop() {
        executor.shutdown()
        channel.close()
    }

    private fun run() {
        val buffer = ByteBuffer.allocateDirect(2048)

        while (true) {
            buffer.clear()
            val peerAddress = channel.receive(buffer) as InetSocketAddress
            buffer.flip()
            logger.info("[SRV] [{}] Received {}", peerAddress, buffer.remaining())

            if (!readPromises.containsKey(peerAddress)) {
                createContext(peerAddress)
            }

            require(readPromises.remove(peerAddress)?.complete(buffer) == true) { "Promise was already completed" }
        }

    }

    private fun receive(adr: InetSocketAddress): CompletableFuture<ByteBuffer> {
        val promise = CompletableFuture<ByteBuffer>()
        val prev = readPromises.put(adr, promise)
        require(prev == null || prev.isDone)
        return promise;
    }

    private fun createContext(peerAddress: InetSocketAddress): SslContext {
        val trans = PeerIOTransport(channel, peerAddress, this::receive)
        val handshakeCtx = sslConfig.newContext(trans)

        handshakeCtx.handshake().thenAccept { readNext(it, peerAddress) }

        return handshakeCtx
    }

    private fun readNext(ctx: SslSession, peerAddress: InetSocketAddress) {
        ctx.read().thenAccept { buf ->
            val resp = handler.invoke(peerAddress, buf)
            if (resp.isNotEmpty()) {
                ctx.send(resp)
            }
            readNext(ctx, peerAddress)
        }
    }

    class PeerIOTransport(
        private val channel: DatagramChannel,
        private val peerAddress: InetSocketAddress,
        private val receiveFun: (InetSocketAddress) -> CompletableFuture<ByteBuffer>
    ) : IOTransport {
        private val logger = LoggerFactory.getLogger(javaClass)

        override fun send(buf: ByteBuffer) {
            logger.info("[SRV] [{}] Sent: {}", peerAddress, buf.remaining())
            channel.send(buf, peerAddress)
        }

        override fun receive(): CompletableFuture<ByteBuffer> = receiveFun.invoke(peerAddress)

    }
}
