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
class DtlsServerTransport private constructor(
    private val transport: Transport<ByteBufferPacket>,
    private val dtlsServer: DtlsServer,
    private val sessionStore: SessionStore,
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
            lifecycleCallbacks: DtlsSessionLifecycleCallbacks = object : DtlsSessionLifecycleCallbacks {},
            cidRequired: Boolean = false
        ): DtlsServerTransport {
            val executor = SingleThreadExecutor.create("dtls-srv-")
            val dtlsServer = DtlsServer(transport, config, expireAfter, sessionStore::write, lifecycleCallbacks, executor, cidRequired)
            return DtlsServerTransport(transport, dtlsServer, sessionStore, executor)
        }
    }

    fun numberOfSessions(): Int = executor.supply { dtlsServer.numberOfSessions }.join()
    fun executor(): ScheduledExecutorService = executor.underlying

    override fun receive(timeout: Duration): CompletableFuture<ByteBufferPacket> {
        return transport.receive(timeout).thenComposeAsync({ packet ->
            if (packet == Packet.EmptyByteBufferPacket) {
                completedFuture(Packet.EmptyByteBufferPacket)
            } else {
                receive0(packet.peerAddress, packet.buffer, timeout)
            }
        }, executor)
    }

    private fun receive0(adr: InetSocketAddress, buf: ByteBuffer, timeout: Duration): CompletableFuture<ByteBufferPacket>? {
        val result = dtlsServer.handleReceived(adr, buf)

        return when (result) {
            is DtlsServer.ReceiveResult.Handled -> receive(timeout)
            is DtlsServer.ReceiveResult.DecryptFailed -> receive(timeout)
            is DtlsServer.ReceiveResult.Decrypted -> completedFuture(result.packet)

            is DtlsServer.ReceiveResult.CidSessionMissing -> {
                val copyBuf = buf.copy()

                sessionStore.read(result.cid).thenApplyAsync(
                    { sessBuf -> dtlsServer.loadSession(sessBuf, adr, result.cid, copyBuf) },
                    executor
                ).thenCompose { isLoaded ->
                    if (isLoaded) {
                        receive0(adr, copyBuf, timeout)
                    } else {
                        receive(timeout)
                    }
                }
            }
        }
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
