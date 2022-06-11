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

import org.awaitility.kotlin.await
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.opencoap.ssl.RandomCidSupplier
import org.opencoap.ssl.SslConfig
import org.opencoap.ssl.SslException
import org.opencoap.ssl.util.await
import org.opencoap.ssl.util.toByteBuffer
import java.net.InetAddress
import java.net.InetSocketAddress
import java.nio.ByteBuffer
import java.nio.channels.DatagramChannel
import kotlin.random.Random

class DtlsServerTest {

    private val psk = Pair("dupa".encodeToByteArray(), byteArrayOf(1))
    private val conf: SslConfig = SslConfig.server(psk.first, psk.second)
    private val certConf = SslConfig.server(Certs.serverChain, Certs.server.privateKey, reqAuthentication = false, cidSupplier = RandomCidSupplier(16))
    private val clientConfig = SslConfig.client(psk.first, psk.second)
    private lateinit var server: DtlsServer
    private val echoHandler: (InetSocketAddress, ByteArray) -> Unit = { adr: InetSocketAddress, packet: ByteArray ->
        if (packet.decodeToString() == "error") {
            throw Exception("error")
        } else {
            server.send(packet.plus(":resp".encodeToByteArray()), adr)
        }
    }

    @AfterEach
    fun tearDown() {
        server.close()
        conf.close()
        clientConfig.close()
    }

    @Test
    fun testSingleConnection() {
        server = DtlsServer.create(conf).listen(echoHandler)

        val client = DtlsTransmitter.connect(server, clientConfig).await()

        client.send("perse")
        assertEquals("perse:resp", client.receiveString())

        assertEquals(1, server.numberOfSessions())
        client.close()
    }

    @Test
    fun testMultipleConnections() {
        server = DtlsServer.create(conf).listen(echoHandler)

        val clients: List<DtlsTransmitter> = (1..10).map {
            val client = DtlsTransmitter.connect(server, clientConfig).await()

            client.send("dupa$it")
            assertEquals("dupa$it:resp", client.receiveString())

            client
        }

        assertEquals(10, server.numberOfSessions())
        clients.forEach(DtlsTransmitter::close)
    }

    @Test
    fun testFailedHandshake() {
        // given
        server = DtlsServer.create(conf).listen(echoHandler)
        val clientFut = DtlsTransmitter.connect(server, SslConfig.client(psk.first, byteArrayOf(-128)))

        // when
        assertTrue(runCatching { clientFut.await() }.exceptionOrNull()?.cause is SslException)

        // then
        await.untilAsserted {
            assertEquals(0, server.numberOfSessions())
        }
    }

    @Test
    fun testReceiveMalformedPacket() {
        // given
        server = DtlsServer.create(conf).listen(echoHandler)
        val client = DtlsTransmitter.connect(server, clientConfig).await()
        client.send("perse")

        // when
        client.cnnTrans.send("malformed dtls packet".toByteBuffer())

        // then
        await.untilAsserted {
            assertEquals(0, server.numberOfSessions())
        }
        client.close()
    }

    @Test
    fun shouldCatchExceptionFromHandler() {
        server = DtlsServer.create(conf).listen(echoHandler)
        val client = DtlsTransmitter.connect(server, clientConfig).await()

        // when
        client.send("error")
        client.send("perse")

        // then
        assertEquals("perse:resp", client.receiveString())

        assertEquals(1, server.numberOfSessions())
        client.close()
    }

    @Test
    fun testMalformedHandshakeMessage() {
        // given
        server = DtlsServer.create(conf).listen(echoHandler)
        val cliChannel: DatagramChannel = DatagramChannel.open()
            .connect(InetSocketAddress(InetAddress.getLocalHost(), server.localPort()))

        // when
        repeat(100) {
            cliChannel.write(ByteBuffer.wrap(Random.nextBytes(50)))
        }

        // then
        await.untilAsserted {
            assertEquals(0, server.numberOfSessions())
        }
        cliChannel.configureBlocking(false)
        assertEquals(0, cliChannel.read("aaa".toByteBuffer()))
        cliChannel.close()
    }

    @Test
    fun `should successfully handshake with certificate`() {
        server = DtlsServer.create(certConf).listen(echoHandler)
        val clientConf = SslConfig.client(trustedCerts = listOf(Certs.root.asX509()))

        // when
        val client = DtlsTransmitter.connect(server, clientConf).await()
        client.send("12345")

        // then
        assertEquals("12345:resp", client.receiveString())
    }

    @Test
    fun `should fail handshake when non trusted certificate`() {
        server = DtlsServer.create(certConf).listen(echoHandler)
        val clientConf = SslConfig.client(trustedCerts = listOf(Certs.rootRsa.asX509()))

        // when
        val result = runCatching { DtlsTransmitter.connect(server, clientConf).await() }

        // then
        assertEquals("X509 - Certificate verification failed, e.g. CRL, CA or signature check failed [-9984]", result.exceptionOrNull()?.cause?.message)
    }
}
