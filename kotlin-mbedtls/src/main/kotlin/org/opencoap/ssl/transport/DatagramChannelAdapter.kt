/*
 * Copyright (c) 2022-2024 kotlin-mbedtls contributors (https://github.com/open-coap/kotlin-mbedtls)
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

import org.slf4j.LoggerFactory
import java.net.InetSocketAddress
import java.nio.ByteBuffer
import java.nio.channels.DatagramChannel
import java.nio.channels.SelectionKey
import java.nio.channels.Selector
import java.time.Duration
import java.util.concurrent.CompletableFuture
import java.util.concurrent.CompletableFuture.completedFuture
import java.util.concurrent.Executors

class DatagramChannelAdapter(
    private val channel: DatagramChannel,
    private val buffer: ByteBuffer = ByteBuffer.allocateDirect(16384)
) : Transport<ByteBufferPacket> {

    companion object {
        fun open(port: Int = 0): Transport<ByteBufferPacket> {
            val datagramChannel = DatagramChannel.open().bind(InetSocketAddress("0.0.0.0", port))
            return DatagramChannelAdapter(datagramChannel)
        }

        fun connect(dest: InetSocketAddress, listenPort: Int = 0): Transport<ByteBuffer> {
            val channel: DatagramChannel = DatagramChannel.open()
            if (listenPort > 0) channel.bind(InetSocketAddress("0.0.0.0", listenPort))
            channel.connect(dest)

            return DatagramChannelAdapter(channel).map(ByteBufferPacket::buffer) { ByteBufferPacket(it, dest) }
        }
    }

    private val logger = LoggerFactory.getLogger(javaClass)
    private val selector: Selector = Selector.open()
    private val port get() = (channel.localAddress as InetSocketAddress).port
    private val executor = Executors.newSingleThreadExecutor { Thread(it, "udp-io (:$port)") }

    init {
        channel.configureBlocking(false)
        channel.register(selector, SelectionKey.OP_READ)
    }

    override fun receive(timeout: Duration): CompletableFuture<ByteBufferPacket> {
        return executor.supply {
            selector.select(timeout.toMillis())
            buffer.clear()

            val sourceAddress = channel.receive(buffer)
            if (sourceAddress == null) {
                logger.trace("[DgramCh:{}] No data received", port)
                Packet.EmptyByteBufferPacket
            } else {
                buffer.flip()
                logger.trace("[DgramCh:{}] Received {} bytes from {}", port, buffer.remaining(), sourceAddress)
                Packet(buffer, sourceAddress as InetSocketAddress)
            }
        }
    }

    override fun send(packet: Packet<ByteBuffer>): CompletableFuture<Boolean> {
        return try {
            logger.trace("[DgramCh:{}] Sent {} bytes to {}", port, packet.buffer.remaining(), packet.peerAddress)
            completedFuture(channel.send(packet.buffer, packet.peerAddress) > 0)
        } catch (ex: Exception) {
            CompletableFuture<Boolean>().also { it.completeExceptionally(ex) }
        }
    }

    override fun close() {
        channel.close()
        selector.close()
        executor.shutdown()
    }

    override fun localPort() = (channel.localAddress as InetSocketAddress).port
}
