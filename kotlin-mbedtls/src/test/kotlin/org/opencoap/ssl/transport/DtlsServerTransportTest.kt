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

import io.mockk.clearMocks
import io.mockk.confirmVerified
import io.mockk.mockk
import io.mockk.verify
import org.awaitility.kotlin.await
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.opencoap.ssl.CertificateAuth
import org.opencoap.ssl.CertificateAuth.Companion.trusted
import org.opencoap.ssl.EmptyCidSupplier
import org.opencoap.ssl.HelloVerifyRequired
import org.opencoap.ssl.PskAuth
import org.opencoap.ssl.RandomCidSupplier
import org.opencoap.ssl.SslConfig
import org.opencoap.ssl.SslException
import org.opencoap.ssl.util.Certs
import org.opencoap.ssl.util.await
import org.opencoap.ssl.util.localAddress
import org.opencoap.ssl.util.mapToString
import org.opencoap.ssl.util.millis
import org.opencoap.ssl.util.seconds
import org.slf4j.LoggerFactory
import java.nio.ByteBuffer
import java.nio.channels.DatagramChannel
import java.time.Duration
import java.util.concurrent.CompletableFuture
import java.util.concurrent.CompletableFuture.completedFuture
import java.util.concurrent.ScheduledThreadPoolExecutor
import java.util.concurrent.TimeUnit
import java.util.function.Consumer
import kotlin.random.Random

class DtlsServerTransportTest {

    private val psk = PskAuth("dupa", byteArrayOf(1))
    private val conf: SslConfig = SslConfig.server(psk, cidSupplier = RandomCidSupplier(6))
    private val certConf = SslConfig.server(CertificateAuth(Certs.serverChain, Certs.server.privateKey), reqAuthentication = false, cidSupplier = RandomCidSupplier(16))
    private val timeoutConf = SslConfig.server(CertificateAuth(Certs.serverChain, Certs.server.privateKey), reqAuthentication = false, cidSupplier = RandomCidSupplier(16), retransmitMin = Duration.ofMillis(20), retransmitMax = Duration.ofMillis(200))

    private val clientConfig = SslConfig.client(psk, cidSupplier = EmptyCidSupplier)
    private val timeoutClientConf = SslConfig.client(CertificateAuth(Certs.dev01Chain, Certs.dev01.privateKey, Certs.root.asX509()), retransmitMin = 20.seconds, retransmitMax = 20.seconds)
    private val sessionStore = HashMapSessionStore()
    private val sslLifecycleCallbacks: DtlsSessionLifecycleCallbacks = mockk(relaxed = true)

    private lateinit var server: DtlsServerTransport

    private val echoHandler: Consumer<ByteBufferPacket> = Consumer<ByteBufferPacket> { packet ->
        val msg = packet.buffer.decodeToString()
        if (msg == "error") {
            throw Exception("error")
        } else if (msg.startsWith("Authenticate:")) {
            server.send(
                Packet(
                    "OK".toByteBuffer(),
                    packet.peerAddress,
                    DtlsSessionContext(authenticationContext = mapOf("auth" to msg.substring(12)))
                )
            )
        } else {
            val ctx = (packet.sessionContext.authenticationContext["auth"] ?: "")
            server.send(packet.map { "$msg:resp$ctx".toByteBuffer() })
        }
    }

    @AfterEach
    fun tearDown() {
        server.close()
        conf.close()
        clientConfig.close()
        timeoutConf.close()
        timeoutClientConf.close()
        sessionStore.clear()
        clearMocks(sslLifecycleCallbacks)
    }

    @Test
    fun testSingleConnection() {
        server = DtlsServerTransport.create(conf, lifecycleCallbacks = sslLifecycleCallbacks)
        val receive = server.receive(10.seconds)

        val client = DtlsTransmitter.connect(server, clientConfig).await().mapToString()

        client.send("hi")
        assertEquals("hi", receive.await().buffer.decodeToString())
        server.send(Packet("czesc".toByteBuffer(), receive.await().peerAddress))
        assertEquals("czesc", client.receive(1.seconds).await())

        repeat(5) { i ->
            client.send("perse$i")
            assertEquals("perse$i", server.receive(1.seconds).await().buffer.decodeToString())
        }

        assertEquals(1, server.numberOfSessions())

        val clientAddress = client.localAddress()
        client.close()

        verify {
            sslLifecycleCallbacks.handshakeStarted(clientAddress)
            sslLifecycleCallbacks.handshakeFinished(clientAddress, any(), any(), DtlsSessionLifecycleCallbacks.Reason.FAILED, ofType(HelloVerifyRequired::class))
            sslLifecycleCallbacks.handshakeStarted(clientAddress)
            sslLifecycleCallbacks.handshakeFinished(clientAddress, any(), any(), DtlsSessionLifecycleCallbacks.Reason.SUCCEEDED)
            sslLifecycleCallbacks.sessionStarted(clientAddress, any(), false)
        }

        // Check no more callbacks are called
        confirmVerified(sslLifecycleCallbacks)
    }

    @Test
    fun testMultipleConnections() {
        val clientCertConf = SslConfig.client(trusted(Certs.root.asX509()), retransmitMin = 60.seconds, retransmitMax = 60.seconds)
        server = DtlsServerTransport.create(certConf).listen(echoHandler)

        val max = 20
        val executors = Array(4) { DtlsTransmitter.newSingleExecutor() }

        val clients = (1..max)
            .map {
                val ch = DatagramChannelAdapter.connect(localAddress(server.localPort()), 0)
                DtlsTransmitter.connect(localAddress(server.localPort()), clientCertConf, ch, executors[it % executors.size])
            }.map {
                it.get(30, TimeUnit.SECONDS)
            }.map { client ->
                val i = Random.nextInt()
                client.send("dupa$i").await()
                assertEquals("dupa$i:resp", client.receiveString())

                client
            }
        assertEquals(max, server.numberOfSessions())
        clients.forEach(DtlsTransmitter::close)
    }

    @Test
    fun testFailedHandshake() {
        // given
        server = DtlsServerTransport.create(conf, lifecycleCallbacks = sslLifecycleCallbacks)
        val srvReceive = server.receive(5.seconds)
        val clientFut = DtlsTransmitter.connect(server, SslConfig.client(psk.copy(pskSecret = byteArrayOf(-128))))

        // when
        val clientResult: Result<DtlsTransmitter> = runCatching { clientFut.await() }
        assertTrue(clientResult.exceptionOrNull()?.cause is SslException, "Expected SslException, but got $clientResult")

        // then
        await.untilAsserted {
            assertEquals(0, server.numberOfSessions())
        }
        assertFalse(srvReceive.isDone)
        verify {
            sslLifecycleCallbacks.handshakeStarted(any())
            sslLifecycleCallbacks.handshakeFinished(any(), any(), any(), DtlsSessionLifecycleCallbacks.Reason.FAILED, ofType(HelloVerifyRequired::class))
            sslLifecycleCallbacks.handshakeStarted(any())
            sslLifecycleCallbacks.handshakeFinished(any(), any(), any(), DtlsSessionLifecycleCallbacks.Reason.FAILED, ofType(SslException::class))
        }

        verify(exactly = 0) {
            sslLifecycleCallbacks.sessionStarted(any(), any(), any())
        }
    }

    @Test
    fun `should discard malformed`() {
        // given
        server = DtlsServerTransport.create(conf, lifecycleCallbacks = sslLifecycleCallbacks).listen(echoHandler)
        val client = DtlsTransmitter.connect(server, clientConfig).await()
        client.send("perse")

        // when
        client.transport.send("malformed dtls packet".toByteBuffer())
        client.send("perse")

        // then
        assertEquals(1, server.numberOfSessions())

        client.close()

        verify {
            sslLifecycleCallbacks.handshakeStarted(any())
            sslLifecycleCallbacks.handshakeFinished(any(), any(), any(), DtlsSessionLifecycleCallbacks.Reason.SUCCEEDED)
            sslLifecycleCallbacks.sessionStarted(any(), any(), any())
        }
    }

    @Test
    fun shouldCatchExceptionFromHandler() {
        server = DtlsServerTransport.create(conf).listen(echoHandler)
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
        server = DtlsServerTransport.create(conf, lifecycleCallbacks = sslLifecycleCallbacks).listen(echoHandler)
        val cliChannel: DatagramChannel = DatagramChannel.open()
            .connect(server.localAddress())

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

        verify(exactly = 0) {
            sslLifecycleCallbacks.handshakeFinished(any(), any(), any(), DtlsSessionLifecycleCallbacks.Reason.FAILED, ofType(HelloVerifyRequired::class))
        }
    }

    @Test
    fun `should successfully handshake with certificate`() {
        server = DtlsServerTransport.create(certConf).listen(echoHandler)
        val clientConf = SslConfig.client(trusted(Certs.root.asX509()))

        // when
        val client = DtlsTransmitter.connect(server, clientConf).await()
        client.send("12345")

        // then
        assertEquals("12345:resp", client.receiveString())
    }

    @Test
    fun `should fail handshake when non trusted certificate`() {
        server = DtlsServerTransport.create(certConf).listen(echoHandler)
        val clientConf = SslConfig.client(trusted(Certs.rootRsa.asX509()))

        // when
        val result = runCatching { DtlsTransmitter.connect(server, clientConf).await() }

        // then
        assertEquals("X509 - Certificate verification failed, e.g. CRL, CA or signature check failed [-0x2700]", result.exceptionOrNull()?.cause?.message)
    }

    @Test
    fun `should send close notify`() {
        server = DtlsServerTransport.create(conf, lifecycleCallbacks = sslLifecycleCallbacks).listen(echoHandler)
        val client = DtlsTransmitter.connect(server, clientConfig).await()
        await.untilAsserted {
            assertEquals(1, server.numberOfSessions())
        }

        // when
        client.closeNotify()

        // then
        await.untilAsserted {
            assertEquals(0, server.numberOfSessions())
        }

        verify {
            sslLifecycleCallbacks.sessionStarted(any(), any(), any())
            sslLifecycleCallbacks.sessionFinished(any(), DtlsSessionLifecycleCallbacks.Reason.CLOSED)
        }
    }

    @Test
    fun `should successfully handshake with retransmission`() {
        server = DtlsServerTransport.create(timeoutConf, lifecycleCallbacks = sslLifecycleCallbacks).listen(echoHandler)
        val cli = DatagramChannelAdapter
            .connect(localAddress(server.localPort()))
            .dropReceive { it == 1 } // drop ServerHello, the only message that server will retry

        // when
        val sslSession = DtlsTransmitter.connect(server.localAddress(), timeoutClientConf, cli)
            .get(30, TimeUnit.SECONDS)
            .also { it.send("something").await() }

        Thread.sleep(500)

        // then
        sslSession.close()
        cli.close()

        // No handshake failures other than HelloVerifyRequired
        verify(exactly = 0) {
            sslLifecycleCallbacks.handshakeFinished(any(), any(), any(), DtlsSessionLifecycleCallbacks.Reason.FAILED, not(ofType(HelloVerifyRequired::class)))
        }

        // One successful handshake must happen
        verify(exactly = 1) {
            sslLifecycleCallbacks.handshakeFinished(any(), any(), any(), DtlsSessionLifecycleCallbacks.Reason.SUCCEEDED)
        }
    }

    @Test
    fun `should remove handshake session when handshake timeout`() {
        server = DtlsServerTransport.create(timeoutConf, lifecycleCallbacks = sslLifecycleCallbacks).listen(echoHandler)
        val cli = DatagramChannelAdapter
            .connect(server.localAddress())
            .dropReceive { it > 0 } // drop everything after client hello with verify

        // when
        DtlsTransmitter.connect(server.localAddress(), timeoutClientConf, cli)

        // then, after some time
        await.untilAsserted {
            assertEquals(0, server.numberOfSessions())
        }

        cli.close()

        verify(exactly = 1) {
            sslLifecycleCallbacks.handshakeFinished(any(), any(), any(), DtlsSessionLifecycleCallbacks.Reason.FAILED, and(ofType(SslException::class), not(ofType(HelloVerifyRequired::class))))
        }
    }

    @Test
    fun `should remove session after inactivity`() {
        // given
        server = DtlsServerTransport.create(conf, expireAfter = 10.millis, lifecycleCallbacks = sslLifecycleCallbacks).listen(echoHandler)
        val client = DtlsTransmitter.connect(server, clientConfig).await()
        client.send("perse")

        // when, inactive

        // then
        await.atMost(1.seconds).untilAsserted {
            assertEquals(0, server.numberOfSessions())
        }
        client.close()

        verify {
            sslLifecycleCallbacks.sessionFinished(any(), DtlsSessionLifecycleCallbacks.Reason.STORED)
            sslLifecycleCallbacks.sessionFinished(any(), DtlsSessionLifecycleCallbacks.Reason.EXPIRED)
        }
    }

    @Test
    fun `should reuse stored session after it is expired`() {
        // given
        server = DtlsServerTransport.create(conf, expireAfter = 100.millis, sessionStore = sessionStore, lifecycleCallbacks = sslLifecycleCallbacks).listen(echoHandler)
        // client connected
        val client = DtlsTransmitter.connect(server, clientConfig).await()
        client.send("Authenticate:dev-007")
        assertEquals("OK", client.receiveString())
        client.send("hi")
        assertEquals("hi:resp:dev-007", client.receiveString())
        // and session is expired and stored
        await.atMost(1.seconds).untilAsserted {
            assertEquals(0, server.numberOfSessions())
        }
        assertEquals(1, sessionStore.size())

        // when
        client.send("hi5")

        // then
        assertEquals("hi5:resp:dev-007", client.receiveString())
        assertEquals(1, server.numberOfSessions())

        await.atMost(1.seconds).untilAsserted {
            assertEquals(0, server.numberOfSessions())
        }
        client.close()

        verify {
            sslLifecycleCallbacks.handshakeStarted(any())
            sslLifecycleCallbacks.handshakeFinished(any(), any(), any(), DtlsSessionLifecycleCallbacks.Reason.FAILED, ofType(HelloVerifyRequired::class))
            sslLifecycleCallbacks.handshakeStarted(any())
            sslLifecycleCallbacks.handshakeFinished(any(), any(), any(), DtlsSessionLifecycleCallbacks.Reason.SUCCEEDED)
            sslLifecycleCallbacks.sessionStarted(any(), any(), false)
            sslLifecycleCallbacks.sessionFinished(any(), DtlsSessionLifecycleCallbacks.Reason.STORED)
            sslLifecycleCallbacks.sessionFinished(any(), DtlsSessionLifecycleCallbacks.Reason.EXPIRED)
            sslLifecycleCallbacks.sessionStarted(any(), any(), true)
            sslLifecycleCallbacks.sessionFinished(any(), DtlsSessionLifecycleCallbacks.Reason.STORED)
            sslLifecycleCallbacks.sessionFinished(any(), DtlsSessionLifecycleCallbacks.Reason.EXPIRED)
        }

        // Check no more callbacks are called
        confirmVerified(sslLifecycleCallbacks)
    }

    @Test
    fun testMultipleClientSendMessagesWithFastExpiration() {
        server = DtlsServerTransport.create(conf, expireAfter = 200.millis, sessionStore = sessionStore).listen(echoHandler)

        val max = 20
        val executors = Array(4) { DtlsTransmitter.newSingleExecutor() }

        // establish dtls connections
        val clients = (1..max)
            .map { clientIndex ->
                val ch = DatagramChannelAdapter.connect(server.localAddress(), 0)
                DtlsTransmitter.connect(server.localAddress(), clientConfig, ch, executors[clientIndex % executors.size])
                    .get(30, TimeUnit.SECONDS)
                    .also { it.send("hello").await() }
            }

        clients.forEach {
            assertEquals("hello:resp", it.receiveString())
        }

        // send messages from different clients at the same time
        val repeat = 10
        val tsStart = System.currentTimeMillis()
        repeat(repeat) {
            clients.forEach { it.send("dupa$it") }
            clients.forEach { assertEquals("dupa$it:resp", it.receiveString()) }
        }
        val totalTs = System.currentTimeMillis() - tsStart
        println("Send %d messages in %d ms (%d/s)".format(max * repeat, totalTs, (1000 * max * repeat) / totalTs))

        clients.forEach(DtlsTransmitter::close)
    }

    @Test
    fun `should export executor without wrapping`() {
        server = DtlsServerTransport.create(conf)

        assertTrue(server.executor() is ScheduledThreadPoolExecutor)
    }

    @Test
    fun `should put client's cid in the session context`() {
        server = DtlsServerTransport.create(conf)
        val serverReceived = server.receive(5.seconds)
        val client = DtlsTransmitter.connect(server, clientConfig).await()
        client.send("hello!")

        assertTrue(client.peerCid.contentEquals(serverReceived.await().sessionContext.cid))

        client.close()
    }

    @Test
    fun `should set and use session context passed inside outbound datagram`() {
        server = DtlsServerTransport.create(conf, expireAfter = 100.millis, sessionStore = sessionStore, lifecycleCallbacks = sslLifecycleCallbacks).listen(echoHandler)
        // client connected
        val client = DtlsTransmitter.connect(server, clientConfig).await()
        client.send("Authenticate:dev-007")
        assertEquals("OK", client.receiveString())
        client.send("hi")
        assertEquals("hi:resp:dev-007", client.receiveString())

        client.close()
    }

    @Test
    fun `server should store session if hinted to do so`() {
        // given
        server = DtlsServerTransport.create(conf, sessionStore = sessionStore)
        val serverReceived = server.receive(10.seconds)
        val client = DtlsTransmitter.connect(server, clientConfig).await().mapToString()

        client.send("dupa")
        server.send(Packet("dupa".toByteBuffer(), serverReceived.await().peerAddress))
        assertEquals("dupa", client.receive(1.seconds).await())

        client.send("sleep")
        server.send(Packet("sleep".toByteBuffer(), serverReceived.await().peerAddress, sessionContext = DtlsSessionContext(sessionSuspensionHint = true)))
        assertEquals("sleep", client.receive(1.seconds).await())

        await.atMost(5.seconds).untilAsserted {
            assertEquals(1, sessionStore.size())
            assertEquals(0, server.numberOfSessions())
        }

        client.close()
    }

    private fun <T> Transport<T>.dropReceive(drop: (Int) -> Boolean): Transport<T> {
        val underlying = this
        var i = 0

        return object : Transport<T> by this {
            private val logger = LoggerFactory.getLogger(javaClass)

            override fun receive(timeout: Duration): CompletableFuture<T> {
                return underlying.receive(timeout)
                    .thenCompose {
                        if (drop(i++)) {
                            logger.info("receive DROPPED {}", it)
                            receive(timeout)
                        } else {
                            logger.info("receive {}", it)
                            completedFuture(it)
                        }
                    }
            }
        }
    }
}

fun Transport<ByteBuffer>.receiveString(): String {
    return receive(Duration.ofSeconds(5)).join().decodeToString()
}
