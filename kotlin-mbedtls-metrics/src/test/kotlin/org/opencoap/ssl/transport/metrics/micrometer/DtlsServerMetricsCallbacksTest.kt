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
import org.junit.jupiter.api.Disabled
import org.junit.jupiter.api.Test
import org.opencoap.ssl.EmptyCidSupplier
import org.opencoap.ssl.PskAuth
import org.opencoap.ssl.RandomCidSupplier
import org.opencoap.ssl.SslConfig
import org.opencoap.ssl.transport.ByteBufferPacket
import org.opencoap.ssl.transport.DatagramChannelAdapter
import org.opencoap.ssl.transport.DtlsServerTransport
import org.opencoap.ssl.transport.DtlsTransmitter
import org.opencoap.ssl.transport.HashMapSessionStore
import org.opencoap.ssl.transport.decodeToString
import org.opencoap.ssl.transport.listen
import org.opencoap.ssl.transport.toByteBuffer
import org.opencoap.ssl.util.await
import org.opencoap.ssl.util.localAddress
import java.nio.ByteBuffer
import java.nio.channels.DatagramChannel
import java.time.Duration
import java.util.function.Consumer
import kotlin.random.Random

class DtlsServerMetricsCallbacksTest {
    private val psk = PskAuth("dupa", byteArrayOf(1))
    private val conf: SslConfig = SslConfig.server(psk, cidSupplier = RandomCidSupplier(6))
    private val clientConfig = SslConfig.client(psk, cidSupplier = EmptyCidSupplier)
    private val meterRegistry = SimpleMeterRegistry()
    private val metricsCallbacks = DtlsServerMetricsCallbacks(meterRegistry)
    private val sessionStore = HashMapSessionStore()

    private lateinit var server: DtlsServerTransport

    private val echoHandler: Consumer<ByteBufferPacket> = Consumer<ByteBufferPacket> { packet ->
        val msg = packet.buffer.decodeToString()
        server.send(packet.map { "$msg:resp".toByteBuffer() })
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
        server = DtlsServerTransport.create(conf, lifecycleCallbacks = metricsCallbacks).listen(echoHandler)

        val client = DtlsTransmitter.connect(server, clientConfig).await()
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
        server = DtlsServerTransport.create(conf, sessionStore = sessionStore, lifecycleCallbacks = metricsCallbacks, expireAfter = Duration.ofMillis(200)).listen(echoHandler)

        val client = DtlsTransmitter.connect(server, clientConfig).await()
        client.send("foo")
        client.receive().await()

        await.atMost(Duration.ofSeconds(1)).untilAsserted {
            assertEquals(0, server.numberOfSessions())
        }

        client.send("bar")
        client.receive().await()

        client.close()

        assertEquals(2, meterRegistry.find("dtls.server.handshakes.initiated").counter()?.count()?.toInt())
        assertEquals(1, meterRegistry.find("dtls.server.handshakes.succeeded").timer()?.count()?.toInt())
        assertEquals(1, meterRegistry.find("dtls.server.sessions.started").tag("suite") { it.isNotEmpty() }.counter()?.count()?.toInt())
        assertEquals(1, meterRegistry.find("dtls.server.sessions.expired").counter()?.count()?.toInt())
        assertEquals(1, meterRegistry.find("dtls.server.sessions.reloaded").counter()?.count()?.toInt())
    }

    @Test
    fun `should report DTLS server metrics for handshake errors`() {
        server = DtlsServerTransport.create(conf, lifecycleCallbacks = metricsCallbacks).listen(echoHandler)
        val cliChannel: DatagramChannel = DatagramChannel.open()
            .connect(localAddress(server.localPort()))

        // when
        cliChannel.write(ByteBuffer.wrap(Random.nextBytes(50)))

        // then
        await.untilAsserted {
            assertEquals(0, server.numberOfSessions())
        }

        assertEquals(1, meterRegistry.find("dtls.server.handshakes.failed").tag("reason") { it.isNotEmpty() }.counter()?.count()?.toInt())
    }

    @Test
    @Disabled
    fun `should report DTLS server metrics for session errors`() {
        // given
        server = DtlsServerTransport.create(conf, lifecycleCallbacks = metricsCallbacks).listen(echoHandler)
        val dest = server.localAddress()
        val transport = DatagramChannelAdapter.connect(dest, 0)
        val client = DtlsTransmitter.connect(dest, clientConfig, transport).await()
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

    @Test
    fun `should report DTLS server metrics for messages drops`() {
        server = DtlsServerTransport.create(conf, lifecycleCallbacks = metricsCallbacks, expireAfter = Duration.ofSeconds(1), sessionStore = sessionStore).listen(echoHandler)
        val serverDest = server.localAddress()

        // Message drop before handshake
        // when
        DatagramChannel.open()
            .connect(localAddress(server.localPort())).write(ByteBuffer.wrap(Random.nextBytes(50)))

        // then
        await.untilAsserted {
            assertEquals(0, server.numberOfSessions())
        }

        assertEquals(1, meterRegistry.find("dtls.server.messages.dropped").counter()?.count()?.toInt())

        // Message drop when a session can't be found in the session store
        val transport = DatagramChannelAdapter.connect(serverDest, 0)
        var client = DtlsTransmitter.connect(serverDest, clientConfig, transport).await()
        client.send("foo").await()
        val session = client.saveSession()

        await.untilAsserted {
            assertEquals(0, server.numberOfSessions())
        }

        // when
        sessionStore.clear()
        client = DtlsTransmitter.create(serverDest, clientConfig.loadSession(byteArrayOf(), session, serverDest))
        client.send("foo").await()

        await.untilAsserted {
            assertEquals(0, server.numberOfSessions())
        }

        // then
        assertEquals(2, meterRegistry.find("dtls.server.messages.dropped").counter()?.count()?.toInt())
    }
}
