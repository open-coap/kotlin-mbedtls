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

import org.opencoap.ssl.SslConfig
import java.net.InetSocketAddress
import java.nio.ByteBuffer
import java.time.Duration
import java.util.concurrent.CompletableFuture
import java.util.concurrent.CompletableFuture.completedFuture
import java.util.concurrent.ScheduledExecutorService
import java.util.concurrent.TimeUnit
import java.util.function.Function

/*
Single threaded dtls server on top of DatagramChannel.
 */
class DtlsServerTransport internal constructor(
    private val transport: Transport<ByteBufferPacket>,
    private val dtlsServer: DtlsServer,
    private val executor: SingleThreadExecutor
) : Transport<ByteBufferPacket> {

    companion object {
        @JvmStatic
        @JvmOverloads
        fun create(
            config: SslConfig,
            listenPort: Int = 0,
            expireAfter: Duration = Duration.ofSeconds(60),
            sessionStore: SessionStore = NoOpsSessionStore,
            transport: Transport<ByteBufferPacket> = DatagramChannelAdapter.open(listenPort),
            lifecycleCallbacks: DtlsSessionLifecycleCallbacks = object : DtlsSessionLifecycleCallbacks {}
        ): DtlsServerTransport {
            val executor = SingleThreadExecutor.create("dtls-srv-")
            val dtlsServer = DtlsServer(transport, config, expireAfter, sessionStore, lifecycleCallbacks, executor)
            return DtlsServerTransport(transport, dtlsServer, executor)
        }
    }

    fun numberOfSessions(): Int = executor.supply { dtlsServer.numberOfSessions }.join()
    fun executor(): ScheduledExecutorService = executor.underlying

    override fun receive(timeout: Duration): CompletableFuture<ByteBufferPacket> {
        return transport.receive(timeout).thenComposeAsync({ packet ->
            if (packet == Packet.EmptyByteBufferPacket) return@thenComposeAsync completedFuture(Packet.EmptyByteBufferPacket)

            val adr: InetSocketAddress = packet.peerAddress
            val buf: ByteBuffer = packet.buffer

            dtlsServer.handleReceived(adr, buf).thenCompose {
                if (it == Packet.EmptyByteBufferPacket) {
                    receive(timeout)
                } else {
                    completedFuture(it)
                }
            }
        }, executor)
    }

    override fun send(packet: Packet<ByteBuffer>): CompletableFuture<Boolean> = executor.supply {
        val encPacket = dtlsServer.encrypt(packet.buffer, packet.peerAddress)?.let(packet::map)

        when (encPacket) {
            null -> completedFuture(false)
            else -> transport.send(encPacket)
        }
    }.thenCompose(Function.identity())

    override fun localPort() = transport.localPort()

    override fun close() {
        executor.supply {
            transport.close()
            dtlsServer.closeSessions()
        }.get(30, TimeUnit.SECONDS)
        executor.shutdown()
    }

    fun putSessionAuthenticationContext(adr: InetSocketAddress, key: String, value: String?): CompletableFuture<Boolean> =
        executor.supply {
            dtlsServer.putSessionAuthenticationContext(adr, key, value)
        }
}
