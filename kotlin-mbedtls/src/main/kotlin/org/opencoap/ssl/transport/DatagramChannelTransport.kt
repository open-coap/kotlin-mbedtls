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

import org.opencoap.ssl.IOTransport
import java.net.InetSocketAddress
import java.nio.ByteBuffer
import java.nio.channels.DatagramChannel
import java.util.concurrent.CompletableFuture
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors

class DatagramChannelTransport(
    val channel: DatagramChannel,
    private val peerAddress: InetSocketAddress,
    val executor: ExecutorService = Executors.newSingleThreadExecutor()
) : IOTransport {

    override fun send(buf: ByteBuffer) {
        channel.send(buf, peerAddress)
    }

    override fun receive(): CompletableFuture<ByteBuffer> {
        return CompletableFuture.supplyAsync(::receivePacket, executor)
    }

    private fun receivePacket(): ByteBuffer {
        val buf = ByteBuffer.allocateDirect(2048)
        channel.receive(buf)
        buf.flip()
        return buf
    }
}
