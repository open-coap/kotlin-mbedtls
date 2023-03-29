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

package org.opencoap.ssl.transport.metrics.micrometer

import io.micrometer.core.instrument.simple.SimpleMeterRegistry
import org.awaitility.kotlin.await
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test
import org.opencoap.ssl.EmptyCidSupplier
import org.opencoap.ssl.PskAuth
import org.opencoap.ssl.RandomCidSupplier
import org.opencoap.ssl.SslConfig
import org.opencoap.ssl.transport.BytesPacket
import org.opencoap.ssl.transport.DatagramChannelAdapter
import org.opencoap.ssl.transport.DtlsServer
import org.opencoap.ssl.transport.DtlsTransmitter
import org.opencoap.ssl.transport.HashMapSessionStore
import org.opencoap.ssl.transport.Packet
import org.opencoap.ssl.transport.listen
import java.net.InetAddress
import java.net.InetSocketAddress
import java.nio.ByteBuffer
import java.nio.channels.DatagramChannel
import java.time.Duration
import java.util.concurrent.TimeUnit
import java.util.function.Consumer
import kotlin.random.Random

class DtlsServerMetricsCallbacksTest {
    private val psk = PskAuth("dupa", byteArrayOf(1))
    private val conf: SslConfig = SslConfig.server(psk, cidSupplier = RandomCidSupplier(6))
    private val clientConfig = SslConfig.client(psk, cidSupplier = EmptyCidSupplier)
    private val meterRegistry = SimpleMeterRegistry()
    private val metricsCallbacks = DtlsServerMetricsCallbacks(meterRegistry)
    private val sessionStore = HashMapSessionStore()

    private lateinit var server: DtlsServer

    private val echoHandler: Consumer<BytesPacket> = Consumer<BytesPacket> { packet ->
        val msg = packet.buffer.decodeToString()
        if (msg == "error") {
            throw Exception("error")
        } else if (msg.startsWith("Authenticate:")) {
            server.putSessionAuthenticationContext(packet.peerAddress, "auth", msg.substring(12))
            server.send(Packet("OK".encodeToByteArray(), packet.peerAddress))
        } else {
            val ctx = packet.sessionContext.authenticationContext
            server.send(packet.map { it.plus(":resp$ctx".encodeToByteArray()) })
        }
    }

    @AfterEach
    fun tearDown() {
        server.close()
        conf.close()
        clientConfig.close()
        meterRegistry.clear()
        sessionStore.clear()
    }

    @Test
    fun `should report DTLS server metrics for happy scenario`() {
        server = DtlsServer.create(conf, lifecycleCallbacks = metricsCallbacks).listen(echoHandler)

        val client = DtlsTransmitter.connect(server, clientConfig).get(5, TimeUnit.SECONDS)
        await.untilAsserted {
            assertEquals(1, server.numberOfSessions())
        }

        client.closeNotify()

        await.untilAsserted {
            assertEquals(0, server.numberOfSessions())
        }

        assertEquals(2, meterRegistry.find("dtls.server.handshakes.initiated").counter()?.count()?.toInt())
        assertEquals(1, meterRegistry.find("dtls.server.handshakes.succeeded").timer()?.count()?.toInt())
        assertEquals(null, meterRegistry.find("dtls.server.handshakes.failed").counter()?.count()?.toInt())
        assertEquals(0, meterRegistry.find("dtls.server.handshakes.expired").counter()?.count()?.toInt())
        assertEquals(1, meterRegistry.find("dtls.server.sessions.started").tag("suite") { it.isNotEmpty() }.counter()?.count()?.toInt())
        assertEquals(null, meterRegistry.find("dtls.server.sessions.failed").counter()?.count()?.toInt())
        assertEquals(0, meterRegistry.find("dtls.server.sessions.expired").counter()?.count()?.toInt())
        assertEquals(0, meterRegistry.find("dtls.server.sessions.reloaded").counter()?.count()?.toInt())
        assertEquals(1, meterRegistry.find("dtls.server.sessions.closed").counter()?.count()?.toInt())
    }

    @Test
    fun `should report DTLS server metrics for expiring sessions`() {
        server = DtlsServer.create(conf, sessionStore = sessionStore, lifecycleCallbacks = metricsCallbacks, expireAfter = Duration.ofMillis(200)).listen(echoHandler)

        val client = DtlsTransmitter.connect(server, clientConfig).get(5, TimeUnit.SECONDS)
        client.send("foo")
        client.receive().get(5, TimeUnit.SECONDS)

        await.atMost(Duration.ofSeconds(1)).untilAsserted {
            assertEquals(0, server.numberOfSessions())
        }

        client.send("bar")
        client.receive().get(5, TimeUnit.SECONDS)

        client.close()

        assertEquals(2, meterRegistry.find("dtls.server.handshakes.initiated").counter()?.count()?.toInt())
        assertEquals(1, meterRegistry.find("dtls.server.handshakes.succeeded").timer()?.count()?.toInt())
        assertEquals(1, meterRegistry.find("dtls.server.sessions.started").tag("suite") { it.isNotEmpty() }.counter()?.count()?.toInt())
        assertEquals(1, meterRegistry.find("dtls.server.sessions.expired").counter()?.count()?.toInt())
        assertEquals(1, meterRegistry.find("dtls.server.sessions.reloaded").counter()?.count()?.toInt())
    }

    @Test
    fun `should report DTLS server metrics for handshake errors`() {
        server = DtlsServer.create(conf, lifecycleCallbacks = metricsCallbacks).listen(echoHandler)
        val cliChannel: DatagramChannel = DatagramChannel.open()
            .connect(InetSocketAddress(InetAddress.getLocalHost(), server.localPort()))

        // when
        cliChannel.write(ByteBuffer.wrap(Random.nextBytes(50)))

        // then
        await.untilAsserted {
            assertEquals(0, server.numberOfSessions())
        }

        assertEquals(1, meterRegistry.find("dtls.server.handshakes.failed").tag("reason") { it.isNotEmpty() }.counter()?.count()?.toInt())
    }

    @Test
    fun `should report DTLS server metrics for session errors`() {
        // given
        server = DtlsServer.create(conf, lifecycleCallbacks = metricsCallbacks).listen(echoHandler)
        val dest = InetSocketAddress(InetAddress.getLocalHost(), server.localPort())
        val transport = DatagramChannelAdapter.connect(dest, 0)
        val client = DtlsTransmitter.connect(dest, clientConfig, transport).get(5, TimeUnit.SECONDS)
        client.send("foo")

        // when
        transport.send(ByteBuffer.wrap("malformed dtls packet".encodeToByteArray()))
        client.send("bar")

        // then
        await.untilAsserted {
            assertEquals(0, server.numberOfSessions())
        }

        client.close()

        print(meterRegistry.metersAsString)
        assertEquals(1, meterRegistry.find("dtls.server.sessions.failed").tag("reason") { it.isNotEmpty() }.counter()?.count()?.toInt())
    }
}
