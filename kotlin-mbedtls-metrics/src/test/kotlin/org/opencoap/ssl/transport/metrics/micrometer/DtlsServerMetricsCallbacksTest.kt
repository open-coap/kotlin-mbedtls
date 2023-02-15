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
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import org.opencoap.ssl.EmptyCidSupplier
import org.opencoap.ssl.PskAuth
import org.opencoap.ssl.RandomCidSupplier
import org.opencoap.ssl.SslConfig
import org.opencoap.ssl.transport.BytesPacket
import org.opencoap.ssl.transport.DtlsServer
import org.opencoap.ssl.transport.DtlsTransmitter
import org.opencoap.ssl.transport.HashMapSessionStore
import org.opencoap.ssl.transport.Packet
import org.opencoap.ssl.transport.listen
import java.util.concurrent.TimeUnit
import java.time.Duration
import java.util.function.Consumer

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
            server.setSessionAuthenticationContext(packet.peerAddress, msg.substring(12))
            server.send(Packet("OK".encodeToByteArray(), packet.peerAddress))
        } else {
            val ctx = (packet.sessionContext.authentication ?: "")
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
        server = DtlsServer.create(conf, lifecycleCallbacks = listOf(metricsCallbacks)).listen(echoHandler)

        val client = DtlsTransmitter.connect(server, clientConfig).get(5, TimeUnit.SECONDS)
        await.untilAsserted {
            assertEquals(1, server.numberOfSessions())
        }

        client.closeNotify()

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
        server = DtlsServer.create(conf, sessionStore = sessionStore, lifecycleCallbacks = listOf(metricsCallbacks), expireAfter = Duration.ofMillis(10)).listen(echoHandler)

        val client = DtlsTransmitter.connect(server, clientConfig).get(5, TimeUnit.SECONDS)
        client.send("foo")

        await.atMost(Duration.ofSeconds(1)).untilAsserted {
            assertEquals(0, server.numberOfSessions())
        }

        client.send("bar")

        assertEquals(2, meterRegistry.find("dtls.server.handshakes.initiated").counter()?.count()?.toInt())
        assertEquals(1, meterRegistry.find("dtls.server.handshakes.succeeded").timer()?.count()?.toInt())
        assertEquals(1, meterRegistry.find("dtls.server.sessions.started").tag("suite") { it.isNotEmpty() }.counter()?.count()?.toInt())
        assertEquals(1, meterRegistry.find("dtls.server.sessions.expired").counter()?.count()?.toInt())
        assertEquals(1, meterRegistry.find("dtls.server.sessions.reloaded").counter()?.count()?.toInt())
    }
}
