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

import java.net.InetSocketAddress
import java.nio.ByteBuffer
import java.nio.channels.DatagramChannel
import java.nio.channels.SelectionKey
import java.nio.channels.Selector
import java.time.Duration
import java.util.concurrent.CompletableFuture
import java.util.concurrent.CompletableFuture.completedFuture
import java.util.concurrent.Executor
import java.util.concurrent.Executors

class DatagramChannelAdapter(
    private val channel: DatagramChannel,
    private val buffer: ByteBuffer = ByteBuffer.allocateDirect(16384),
    private val executor: Executor = Executors.newSingleThreadExecutor { Thread(it, "udp-io (:${channel.localPort()})") }
) : Transport<ByteBufferPacket> {

    companion object {
        fun open(port: Int = 0): Transport<ByteBufferPacket> {
            val datagramChannel = DatagramChannel.open().bind(InetSocketAddress("0.0.0.0", port))
            return DatagramChannelAdapter(datagramChannel)
        }

        fun connect(dest: InetSocketAddress, listenPort: Int = 0): Transport<ByteBuffer> {
            val channel: DatagramChannel = newDatagramChannel(listenPort, dest)

            return DatagramChannelAdapter(channel).map(ByteBufferPacket::buffer) { ByteBufferPacket(it, dest) }
        }

        private fun newDatagramChannel(listenPort: Int, dest: InetSocketAddress): DatagramChannel {
            val channel: DatagramChannel = DatagramChannel.open()
            if (listenPort > 0) channel.bind(InetSocketAddress("0.0.0.0", listenPort))
            channel.connect(dest)
            return channel
        }

        fun connectBlocking(dest: InetSocketAddress, listenPort: Int = 0): Transport<ByteBuffer> {
            return DatagramChannelAdapter(
                channel = newDatagramChannel(listenPort, dest),
                executor = Runnable::run // makes blocking receiving
            ).map(ByteBufferPacket::buffer) { ByteBufferPacket(it, dest) }
        }
    }

    private val selector: Selector = Selector.open()

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
                Packet.EmptyByteBufferPacket
            } else {
                buffer.flip()
                Packet(buffer, sourceAddress as InetSocketAddress)
            }
        }
    }

    override fun send(packet: Packet<ByteBuffer>): CompletableFuture<Boolean> {
        return try {
            completedFuture(channel.send(packet.buffer, packet.peerAddress) > 0)
        } catch (ex: Exception) {
            CompletableFuture<Boolean>().also { it.completeExceptionally(ex) }
        }
    }

    override fun close() {
        channel.close()
        selector.close()
        // executor.shutdown()
    }

    override fun localPort() = (channel.localAddress as InetSocketAddress).port
}

private fun DatagramChannel.localPort(): Int = (localAddress as InetSocketAddress).port
