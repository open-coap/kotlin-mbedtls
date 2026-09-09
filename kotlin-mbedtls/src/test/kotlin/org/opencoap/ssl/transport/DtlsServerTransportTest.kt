/*
 * Copyright (c) 2022-2026 kotlin-mbedtls contributors (https://github.com/open-coap/kotlin-mbedtls)
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
import org.opencoap.ssl.util.truncatedDtlsHandshakeHeader
import org.slf4j.LoggerFactory
import java.nio.ByteBuffer
import java.nio.channels.ClosedChannelException
import java.nio.channels.DatagramChannel
import java.time.Duration
import java.util.concurrent.CompletableFuture
import java.util.concurrent.CompletableFuture.completedFuture
import java.util.concurrent.ScheduledThreadPoolExecutor
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
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

    // Any datagram shorter than the 14 bytes that isValidHandshakeRequest reads used to throw
    // out of DtlsServer.handleReceived(), which reached Transport.listen()'s `handle` callback
    // as `err != null` and ended the receive loop for good. After the fix the server must drop
    // every one of them and keep serving legitimate clients.
    @Test
    fun `should survive short malformed datagrams and keep serving`() {
        server = DtlsServerTransport.create(conf, lifecycleCallbacks = sslLifecycleCallbacks).listen(echoHandler)
        val cliChannel = DatagramChannel.open().connect(server.localAddress())
        try {
            for (len in 0..13) {
                cliChannel.write(ByteBuffer.wrap(truncatedDtlsHandshakeHeader.copyOf(len)))
            }
        } finally {
            cliChannel.close()
        }

        // server is still alive: a legitimate client can still handshake and exchange data
        val client = DtlsTransmitter.connect(server, clientConfig).await()
        client.send("ok-after-junk")
        assertEquals("ok-after-junk:resp", client.receiveString())
        client.close()
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

        verify(exactly = 1) {
            sslLifecycleCallbacks.sessionFinished(any(), DtlsSessionLifecycleCallbacks.Reason.STORED)
        }
        verify(exactly = 0) {
            sslLifecycleCallbacks.sessionFinished(any(), DtlsSessionLifecycleCallbacks.Reason.EXPIRED)
        }
    }

    @Test
    fun `should not store session when peer sent no application data`() {
        // given, mbedTLS holds on to the server handshake structure until the peer sends a record,
        // and refuses to serialise a context that still has one
        server = DtlsServerTransport.create(conf, expireAfter = 10.millis, sessionStore = sessionStore, lifecycleCallbacks = sslLifecycleCallbacks).listen(echoHandler)
        val client = DtlsTransmitter.connect(server, clientConfig).await()

        // when, the session idles out without ever carrying application data
        await.atMost(1.seconds).untilAsserted {
            assertEquals(0, server.numberOfSessions())
        }
        client.close()

        // then, it is reported once, and not as a failure
        verify(exactly = 1) {
            sslLifecycleCallbacks.sessionFinished(any(), DtlsSessionLifecycleCallbacks.Reason.EXPIRED)
        }
        verify(exactly = 0) {
            sslLifecycleCallbacks.sessionFinished(any(), DtlsSessionLifecycleCallbacks.Reason.FAILED, any())
            sslLifecycleCallbacks.sessionFinished(any(), DtlsSessionLifecycleCallbacks.Reason.STORED)
        }
        assertEquals(0, sessionStore.size())
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
            sslLifecycleCallbacks.sessionStarted(any(), any(), true)
            sslLifecycleCallbacks.sessionFinished(any(), DtlsSessionLifecycleCallbacks.Reason.STORED)
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

    @Test
    fun `should keep listening after receive fails`() {
        // given, packet handling blows up for a specific payload
        server = DtlsServerTransport.create(conf)
        server.failReceive { it == "poison" }.listen(echoHandler)
        val client = DtlsTransmitter.connect(server, clientConfig).await()

        // when
        client.send("poison")

        // then the listener kept reading
        client.send("perse")
        assertEquals("perse:resp", client.receiveString())

        // and a brand new client can still handshake and echo
        val client2 = DtlsTransmitter.connect(server, clientConfig).await()
        client2.send("hi")
        assertEquals("hi:resp", client2.receiveString())

        client.close()
        client2.close()
    }

    @Test
    fun `should not accumulate pending receives when receive keeps failing`() {
        // given
        val poisonCount = 1000
        val maxInFlight = AtomicInteger(0)
        server = DtlsServerTransport.create(conf)
        server.failReceive { it == "poison" }.trackInFlight(maxInFlight).listen(echoHandler)
        val client = DtlsTransmitter.connect(server, clientConfig).await()

        // when
        repeat(poisonCount) { client.send("poison") }

        // then still serving traffic, datagrams may have been dropped by the socket so keep retrying
        await.atMost(30.seconds).untilAsserted {
            client.send("perse")
            assertEquals("perse:resp", client.receive(500.millis).await().decodeToString())
        }

        // and the loop keeps exactly one receive outstanding, no matter how many of them failed
        assertEquals(1, maxInFlight.get())

        // and scheduled tasks stay bounded by packets received, not by failures. They do not reach zero: every
        // decrypted packet makes DtlsSession reschedule its expiry task and the cancelled one lingers in the
        // queue, which happens for good packets just the same.
        assertTrue((server.executor() as ScheduledThreadPoolExecutor).queue.size <= poisonCount + 100)

        client.close()
    }

    @Test
    fun `should stop listening when transport is gone`() {
        // given, a transport that stays submittable but fails every receive once closed
        val receiveCount = AtomicInteger(0)
        val gone = AtomicBoolean(false)
        val underlying = DatagramChannelAdapter.open(0)
        val transport = object : Transport<ByteBufferPacket> by underlying {
            override fun receive(timeout: Duration): CompletableFuture<ByteBufferPacket> {
                receiveCount.incrementAndGet()
                if (!gone.get()) return underlying.receive(timeout)
                return CompletableFuture<ByteBufferPacket>().also { it.completeExceptionally(ClosedChannelException()) }
            }
        }
        server = DtlsServerTransport.create(conf, transport = transport).listen(echoHandler)
        val client = DtlsTransmitter.connect(server, clientConfig).await()
        client.send("hi")
        assertEquals("hi:resp", client.receiveString())

        // when
        gone.set(true)
        client.send("hi") // completes the pending receive, so that the loop reschedules and hits the closed transport
        Thread.sleep(500)

        // then the loop terminated, it is not spinning on failed receives
        val stoppedAt = receiveCount.get()
        Thread.sleep(500)
        assertEquals(stoppedAt, receiveCount.get())

        client.close()
    }

    // records the highest number of receives that were outstanding at the same time
    private fun <T> Transport<T>.trackInFlight(max: AtomicInteger): Transport<T> {
        val underlying = this
        val inFlight = AtomicInteger(0)

        return object : Transport<T> by this {
            override fun receive(timeout: Duration): CompletableFuture<T> {
                val current = inFlight.incrementAndGet()
                max.accumulateAndGet(current) { a, b -> maxOf(a, b) }
                return underlying.receive(timeout).whenComplete { _, _ -> inFlight.decrementAndGet() }
            }
        }
    }

    // fails packet handling for every packet matching [poison], as an unexpected exception in the receive path would
    private fun DtlsServerTransport.failReceive(poison: (String) -> Boolean): Transport<ByteBufferPacket> {
        val underlying = this

        return object : Transport<ByteBufferPacket> by this {
            override fun receive(timeout: Duration): CompletableFuture<ByteBufferPacket> = underlying.receive(timeout)
                .thenCompose { packet ->
                    if (poison(packet.buffer.duplicate().decodeToString())) {
                        CompletableFuture<ByteBufferPacket>().also { it.completeExceptionally(IllegalStateException("packet handling blew up")) }
                    } else {
                        completedFuture(packet)
                    }
                }
        }
    }

    private fun <T> Transport<T>.dropReceive(drop: (Int) -> Boolean): Transport<T> {
        val underlying = this
        var i = 0

        return object : Transport<T> by this {
            private val logger = LoggerFactory.getLogger(javaClass)

            override fun receive(timeout: Duration): CompletableFuture<T> = underlying.receive(timeout)
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

fun Transport<ByteBuffer>.receiveString(): String = receive(Duration.ofSeconds(5)).join().decodeToString()
