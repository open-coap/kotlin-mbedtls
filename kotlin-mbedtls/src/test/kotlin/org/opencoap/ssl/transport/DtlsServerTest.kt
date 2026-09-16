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
import io.mockk.mockk
import io.mockk.verify
import org.awaitility.kotlin.await
import org.junit.jupiter.api.AfterAll
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestInstance
import org.opencoap.ssl.CertificateAuth
import org.opencoap.ssl.CidSupplier
import org.opencoap.ssl.RandomCidSupplier
import org.opencoap.ssl.SslConfig
import org.opencoap.ssl.SslSession
import org.opencoap.ssl.transport.DtlsServer.ReceiveResult
import org.opencoap.ssl.util.Certs
import org.opencoap.ssl.util.StoredSessionPair
import org.opencoap.ssl.util.decodeHex
import org.opencoap.ssl.util.flip0
import org.opencoap.ssl.util.localAddress
import org.opencoap.ssl.util.millis
import org.opencoap.ssl.util.readByteAndSeek
import org.opencoap.ssl.util.readShortAndSeek
import org.opencoap.ssl.util.seek
import org.opencoap.ssl.util.truncatedDtlsHandshakeHeader
import org.opencoap.ssl.util.withFlippedBitAt
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.time.Instant
import java.util.LinkedList
import java.util.concurrent.CompletableFuture
import java.util.concurrent.CompletableFuture.completedFuture
import kotlin.random.Random

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class DtlsServerTest {
    companion object {
        // CID of the stored session pair
        private val SRV_CID = "f935adc57425e1b214f8640d56e0c733".decodeHex()
    }

    val serverConf = SslConfig.server(CertificateAuth(Certs.serverChain, Certs.server.privateKey), listOf("TLS-ECDHE-ECDSA-WITH-AES-128-GCM-SHA256"), false, RandomCidSupplier(16))
    val clientConf = SslConfig.client(CertificateAuth.trusted(Certs.root.asX509()), cipherSuites = listOf("TLS-ECDHE-ECDSA-WITH-AES-128-GCM-SHA256"))
    val clientConfNoCid = SslConfig.client(CertificateAuth.trusted(Certs.root.asX509()), cipherSuites = listOf("TLS-ECDHE-ECDSA-WITH-AES-128-GCM-SHA256"), cidSupplier = null)
    val serverConfInvalidCid = SslConfig.server(CertificateAuth(Certs.serverChain, Certs.server.privateKey), listOf("TLS-ECDHE-ECDSA-WITH-AES-128-GCM-SHA256"), false, InvalidCidSupplier(16))

    private val adr = localAddress(2_5684)
    private val sessionStore = HashMapSessionStore()
    private val lifecycleCallbacks: DtlsSessionLifecycleCallbacks = mockk(relaxed = true)
    private lateinit var dtlsServer: DtlsServer
    private val serverOutboundQueue = LinkedList<ByteBuffer>()

    @BeforeEach
    fun setUp() {
        // PER_CLASS shares the store, and tearDown stores any session still live
        sessionStore.clear()
        dtlsServer = DtlsServer(::outboundTransport, serverConf, 100.millis, sessionStore::write, lifecycleCallbacks, executor = SingleThreadExecutor.create("dtls-srv-"))
    }

    private fun outboundTransport(it: ByteBufferPacket): CompletableFuture<Boolean> {
        serverOutboundQueue.add(it.buffer.copy())
        return completedFuture(true)
    }

    @AfterEach
    fun tearDown() {
        dtlsServer.closeSessions()
        clearMocks(lifecycleCallbacks)
    }

    @AfterAll
    fun afterAll() {
        serverConf.close()
        clientConf.close()
    }

    @Test
    fun `should load session from store and exchange messages`() {
        val clientSession = clientConf.loadSession(byteArrayOf(), StoredSessionPair.cliSession, localAddress(5684))

        val dtlsPacket = clientSession.encrypt("hello".toByteBuffer()).order(ByteOrder.BIG_ENDIAN)
        assertTrue(dtlsServer.handleReceived(localAddress(2_5684), dtlsPacket) is ReceiveResult.CidSessionMissing)

        // when
        dtlsServer.loadSession(SessionWithContext(StoredSessionPair.srvSession, mapOf(), Instant.ofEpochSecond(123456789)), localAddress(2_5684), "f935adc57425e1b214f8640d56e0c733".decodeHex(), dtlsPacket)

        // then
        val dtlsPacketIn = (dtlsServer.handleReceived(localAddress(2_5684), dtlsPacket) as ReceiveResult.Decrypted).packet
        assertEquals("hello", dtlsPacketIn.buffer.decodeToString())
        assertEquals(Instant.ofEpochSecond(123456789), dtlsPacketIn.sessionContext.sessionStartTimestamp)
        val dtlsPacketOut = dtlsServer.encrypt("hello2".toByteBuffer(), localAddress(2_5684))!!.order(ByteOrder.BIG_ENDIAN)
        assertEquals("hello2", clientSession.decrypt(dtlsPacketOut, noSend).decodeToString())

        clientSession.close()
    }

    @Test
    fun `should keep reloaded session when the record that triggered the load is replayed`() {
        // given, a session that was reloaded, used and then stored back
        val (clientSession, replayedRecord) = reloadedAndStoredBackSession()
        clearMocks(lifecycleCallbacks)

        // when, the already seen record arrives again and drives another reload
        val result = dtlsServer.loadSession(sessionStore.read(SRV_CID).join(), adr, SRV_CID, replayedRecord.duplicate())

        // then, the record is dropped but the session survives
        assertTrue(result is DtlsServer.SessionLoadResult.RecordVerificationFailed)
        assertEquals(1, dtlsServer.numberOfSessions)
        verify(exactly = 1) { lifecycleCallbacks.messageDropped(adr) }

        // and, the next genuine record from the same peer is served normally
        val next = clientSession.encrypt("recovered".toByteBuffer()).order(ByteOrder.BIG_ENDIAN)
        assertEquals("recovered", dtlsServer.handleAndDecrypt(next))

        clientSession.close()
    }

    @Test
    fun `should store retained session back through idle expiry only`() {
        // given, a reloaded session retained after rejecting a replayed record
        val (clientSession, replayedRecord) = reloadedAndStoredBackSession()
        dtlsServer.loadSession(sessionStore.read(SRV_CID).join(), adr, SRV_CID, replayedRecord.duplicate())
        assertEquals(1, dtlsServer.numberOfSessions)

        // then, nothing is written back on the rejection path itself
        assertEquals(0, sessionStore.size())

        // when, the session goes idle
        await.untilAsserted {
            assertEquals(0, dtlsServer.numberOfSessions)
        }

        // then, the normal idle-expiry path stored it
        assertEquals(1, sessionStore.size())
        assertNotNull(sessionStore.read(SRV_CID).join())

        clientSession.close()
    }

    @Test
    fun `should discard reloaded session when the record that triggered the load is tampered`() {
        val clientSession = clientConf.loadSession(byteArrayOf(), StoredSessionPair.cliSession, localAddress(5684))
        val record = clientSession.encrypt("hello".toByteBuffer()).order(ByteOrder.BIG_ENDIAN).copy()
        // a fresh record fails the MAC rather than the replay window
        val tampered = record.withFlippedBitAt(record.remaining() - 1).order(ByteOrder.BIG_ENDIAN)

        // when
        val result = dtlsServer.loadSession(SessionWithContext(StoredSessionPair.srvSession, mapOf(), Instant.now()), adr, SRV_CID, tampered)

        // then, the record is dropped and no session is left behind
        assertTrue(result is DtlsServer.SessionLoadResult.RecordVerificationFailed)
        assertEquals(0, dtlsServer.numberOfSessions)
        verify(exactly = 1) { lifecycleCallbacks.messageDropped(adr) }

        clientSession.close()
    }

    @Test
    fun `should ignore when session not found in store`() {
        val clientSession = clientConf.loadSession(byteArrayOf(), StoredSessionPair.cliSession, localAddress(2_5684))

        val dtlsPacket = clientSession.encrypt("hello".toByteBuffer()).order(ByteOrder.BIG_ENDIAN)
        assertTrue(dtlsServer.handleReceived(localAddress(2_5684), dtlsPacket) is ReceiveResult.CidSessionMissing)

        clientSession.close()
    }

    @Test
    fun `should silently drop when CID is invalid`() {
        dtlsServer = DtlsServer(::outboundTransport, serverConfInvalidCid, 100.millis, sessionStore::write, executor = SingleThreadExecutor.create("dtls-srv-"), cidRequired = true)
        val dtlsPacket = "19fefd0001000000000002 bad0bad0bad0bad0bad0bad0bad0bad0 00280001000000000002c113fbaee67f6ce621628812750f3d0f3cb5f0d43bb358f1b502a91404098252".replace(" ", "").decodeHex().asByteBuffer()
        assertTrue(dtlsServer.handleReceived(localAddress(2_5684), dtlsPacket) is ReceiveResult.Handled)
    }

    @Test
    fun `should handshake`() {
        // when
        val clientSession = clientHandshake()

        // then
        val dtlsPacket = clientSession.encrypt("terve".toByteBuffer()).order(ByteOrder.BIG_ENDIAN)
        val dtlsPacketIn = (dtlsServer.handleReceived(localAddress(2_5684), dtlsPacket) as ReceiveResult.Decrypted).packet
        assertEquals("terve", dtlsPacketIn.buffer.decodeToString())
        assertEquals(1, dtlsServer.numberOfSessions)
        assertNotNull(dtlsPacketIn.sessionContext.sessionStartTimestamp)

        await.untilAsserted {
            assertTrue(serverOutboundQueue.isEmpty())
        }

        clientSession.close()
    }

    @Test
    fun `should handshake when CID is required`() {
        dtlsServer = DtlsServer(::outboundTransport, serverConf, 100.millis, sessionStore::write, executor = SingleThreadExecutor.create("dtls-srv-"), cidRequired = true)

        // when
        val clientSession = clientHandshake()

        // then
        val dtlsPacket = clientSession.encrypt("terve".toByteBuffer()).order(ByteOrder.BIG_ENDIAN)
        val dtlsPacketIn = (dtlsServer.handleReceived(localAddress(2_5684), dtlsPacket) as ReceiveResult.Decrypted).packet
        assertEquals("terve", dtlsPacketIn.buffer.decodeToString())
        assertEquals(1, dtlsServer.numberOfSessions)
        assertNotNull(dtlsPacketIn.sessionContext.sessionStartTimestamp)

        await.untilAsserted {
            assertTrue(serverOutboundQueue.isEmpty())
        }

        clientSession.close()
    }

    @Test
    fun `should fail handshake when CID is required and client doesn't provide it`() {
        dtlsServer = DtlsServer(::outboundTransport, serverConf, 100.millis, sessionStore::write, executor = SingleThreadExecutor.create("dtls-srv-"), cidRequired = true)
        val send: (ByteBuffer) -> Unit = { dtlsServer.handleReceived(localAddress(2_5684), it) }
        val cliHandshake = clientConfNoCid.newContext(localAddress(5684))

        // when
        cliHandshake.step(send)

        // then
        await.untilAsserted {
            assertTrue(serverOutboundQueue.isEmpty())
        }
    }

    @Test
    fun `should handshake with replaying records`() {
        lateinit var sendingBuffer: ByteBuffer
        val send: (ByteBuffer) -> Unit = { sendingBuffer = it }
        val cliHandshake = clientConf.newContext(localAddress(5684))

        cliHandshake.step(send)

        println("Flight 1")
        dtlsServer.handleReceived(localAddress(2_5684), sendingBuffer)
        dtlsServer.handleReceived(localAddress(2_5684), sendingBuffer.flip0()) // replayed record
        cliHandshake.step(serverOutboundQueue.remove(), send)
        cliHandshake.step(serverOutboundQueue.remove(), send)

        println("Flight  2")
        dtlsServer.handleReceived(localAddress(2_5684), sendingBuffer)
        dtlsServer.handleReceived(localAddress(2_5684), sendingBuffer.flip0()) // replayed record
        cliHandshake.step(serverOutboundQueue.remove(), send)

        println("Flight  3")
        dtlsServer.handleReceived(localAddress(2_5684), sendingBuffer)
        assertTrue(dtlsServer.handleReceived(localAddress(2_5684), sendingBuffer.flip0()) is ReceiveResult.Handled) // replayed record
        val clientSession = cliHandshake.step(serverOutboundQueue.remove(), send) as SslSession

        println("Flights over")
        val dtlsPacket = clientSession.encrypt("terve".toByteBuffer()).order(ByteOrder.BIG_ENDIAN)
        assertEquals("terve", dtlsServer.handleAndDecrypt(dtlsPacket))
        //  replayed record
        assertTrue(dtlsServer.handleReceived(localAddress(2_5684), dtlsPacket) is ReceiveResult.Handled)
        assertTrue(dtlsServer.handleReceived(localAddress(2_5684), dtlsPacket) is ReceiveResult.Handled)

        // replayed record from handshake
        assertTrue(dtlsServer.handleReceived(localAddress(2_5684), sendingBuffer.flip0()) is ReceiveResult.Handled)

        assertTrue(serverOutboundQueue.isEmpty())
        clientSession.close()
    }

    @Test
    fun `should handshake with client retransmission`() {
        val send: (ByteBuffer) -> Unit = { dtlsServer.handleReceived(localAddress(2_5684), it) }
        val cliHandshake = clientConf.newContext(localAddress(5684))

        cliHandshake.step(send)
        cliHandshake.step(serverOutboundQueue.remove(), send)

        // Drop and trigger resend
        println("DROP " + serverOutboundQueue.size)
        serverOutboundQueue.remove()
        cliHandshake.step(Packet.EMPTY_BYTEBUFFER, send)

        cliHandshake.step(serverOutboundQueue.remove(), send)
        val clientSession = cliHandshake.step(serverOutboundQueue.remove(), send) as SslSession

        val dtlsPacket = clientSession.encrypt("terve".toByteBuffer()).order(ByteOrder.BIG_ENDIAN)
        assertEquals("terve", dtlsServer.handleAndDecrypt(dtlsPacket))

        assertTrue(serverOutboundQueue.isEmpty())

        clientSession.close()
    }

    @Test
    fun `should handshake with client retransmission of last flight`() {
        val send: (ByteBuffer) -> Unit = { dtlsServer.handleReceived(localAddress(2_5684), it) }
        val cliHandshake = clientConf.newContext(localAddress(5684))

        cliHandshake.step(send)
        cliHandshake.step(serverOutboundQueue.remove(), send)
        cliHandshake.step(serverOutboundQueue.remove(), send)

        // Drop and trigger resend
        println("DROP " + serverOutboundQueue.size)
        serverOutboundQueue.remove()
        cliHandshake.step(Packet.EMPTY_BYTEBUFFER, send)

        val clientSession = cliHandshake.step(serverOutboundQueue.remove(), send) as SslSession

        val dtlsPacket = clientSession.encrypt("terve".toByteBuffer()).order(ByteOrder.BIG_ENDIAN)
        assertEquals("terve", dtlsServer.handleAndDecrypt(dtlsPacket))

        assertTrue(serverOutboundQueue.isEmpty())
        clientSession.close()
    }

    @Test
    fun `should remove session after inactivity`() {
        // given
        val clientSession = clientHandshake()
        assertEquals(1, dtlsServer.numberOfSessions)
        val dtlsPacket = clientSession.encrypt("terve".toByteBuffer()).order(ByteOrder.BIG_ENDIAN)
        assertEquals("terve", dtlsServer.handleAndDecrypt(dtlsPacket))

        // when, inactivity
        await.untilAsserted {
            assertEquals(0, dtlsServer.numberOfSessions)
        }

        clientSession.close()
    }

    @Test
    fun `should remove session after inactivity without incoming application record`() {
        // given
        val clientSession = clientHandshake()
        assertEquals(1, dtlsServer.numberOfSessions)
        // and nothing is sent to server

        // when, inactivity
        await.untilAsserted {
            assertEquals(0, dtlsServer.numberOfSessions)
        }

        clientSession.close()
    }

    @Test
    fun `should properly seek through the buffer`() {
        var buf = ByteBuffer.wrap("FFFF01FF0001FF".decodeHex())
        buf.position(1)
        buf.seek(1)
        buf.seek(-2)
        buf.seek(2)
        assertEquals(2, buf.position())
        buf.readByteAndSeek()
        assertEquals(4, buf.position())
        buf.readShortAndSeek()
        assertEquals(7, buf.position())

        buf = ByteBuffer.wrap("FF".decodeHex() + ByteArray(255) + "FFFF".decodeHex() + ByteArray(65535))
        buf.readByteAndSeek()
        assertEquals(256, buf.position())
        buf.readShortAndSeek()
        assertEquals(65793, buf.position())
    }

    // isValidHandshakeRequest reads 8 bytes at offset 0 and one byte at offset 13. Before the
    // bound check, every length below 14 threw out of handleReceived() rather than being
    // rejected: 0-7 failed the 8-byte read, 8-13 passed the header check and then failed the
    // handshake-type read.
    @Test
    fun `should drop datagrams shorter than the handshake header`() {
        val adr = localAddress(2_5684)

        for (len in 0..13) {
            val result = dtlsServer.handleReceived(adr, ByteBuffer.wrap(truncatedDtlsHandshakeHeader.copyOf(len)))
            assertTrue(result is ReceiveResult.Handled, "expected Handled for length $len, got $result")
        }

        assertEquals(0, dtlsServer.numberOfSessions)
        verify(exactly = 14) { lifecycleCallbacks.messageDropped(adr) }
    }

    @Test
    fun `should not throw for randomised datagrams`() {
        val random = Random(1)
        val adr = localAddress(2_5684)

        repeat(20_000) {
            dtlsServer.handleReceived(adr, ByteBuffer.wrap(random.nextBytes(random.nextInt(0, 301))))
        }

        // nothing random passed as a handshake, so the parse path stayed a pure filter
        assertEquals(0, dtlsServer.numberOfSessions)
    }

    // supportsCid() walks from offset 59, but isValidHandshakeRequest only guards 14 bytes.
    // Before the bound checks, every length in 14..65 that passed the sniff threw out of
    // handleReceived(). The 0f73c72 fuzz test runs with cidRequired = false, so it never hit this.
    @Test
    fun `should drop short datagrams when CID is required`() {
        dtlsServer = DtlsServer(::outboundTransport, serverConf, 100.millis, sessionStore::write, lifecycleCallbacks, executor = SingleThreadExecutor.create("dtls-srv-"), cidRequired = true)
        val adr = localAddress(2_5684)

        // passes the sniff: Handshake(0x16), DTLS 1.2, epoch 0, ClientHello(1) at offset 13
        val clientHelloHeader = "16fefd0000000000000000000001".decodeHex()

        for (len in 0..120) {
            val bytes = clientHelloHeader.copyOf(len.coerceAtMost(clientHelloHeader.size)) +
                ByteArray((len - clientHelloHeader.size).coerceAtLeast(0))
            val result = dtlsServer.handleReceived(adr, ByteBuffer.wrap(bytes))
            assertTrue(result is ReceiveResult.Handled, "expected Handled for length $len, got $result")
        }

        assertEquals(0, dtlsServer.numberOfSessions)
    }

    @Test
    fun `should not throw for randomised datagrams when CID is required`() {
        dtlsServer = DtlsServer(::outboundTransport, serverConf, 100.millis, sessionStore::write, lifecycleCallbacks, executor = SingleThreadExecutor.create("dtls-srv-"), cidRequired = true)
        val random = Random(1)
        val adr = localAddress(2_5684)

        repeat(20_000) {
            // half get a valid-looking header, so the fuzz reaches the walk instead of the sniff
            val body = random.nextBytes(random.nextInt(0, 301))
            val bytes = if (random.nextBoolean()) "16fefd0000000000000000000001".decodeHex() + body else body
            dtlsServer.handleReceived(adr, ByteBuffer.wrap(bytes))
        }

        assertEquals(0, dtlsServer.numberOfSessions)
    }

    private fun clientHandshake(): SslSession {
        val send: (ByteBuffer) -> Unit = { dtlsServer.handleReceived(localAddress(2_5684), it) }
        val cliHandshake = clientConf.newContext(localAddress(5684))

        cliHandshake.step(send)
        cliHandshake.step(serverOutboundQueue.remove(), send)
        cliHandshake.step(serverOutboundQueue.remove(), send)
        return cliHandshake.step(serverOutboundQueue.remove(), send) as SslSession
    }

    private val noSend: (ByteBuffer) -> Unit = { throw IllegalStateException() }

    // Reloads the stored session pair and feeds it one record, so that record is now inside the
    // replay window, then stores the session back. Returns the record ready to be replayed.
    private fun reloadedAndStoredBackSession(): Pair<SslSession, ByteBuffer> {
        val clientSession = clientConf.loadSession(byteArrayOf(), StoredSessionPair.cliSession, localAddress(5684))
        // encrypt returns a view over a reused native buffer, so copy to survive the next one
        val record = clientSession.encrypt("hello".toByteBuffer()).order(ByteOrder.BIG_ENDIAN).copy()
        dtlsServer.loadSession(SessionWithContext(StoredSessionPair.srvSession, mapOf(), Instant.now()), adr, SRV_CID, record.duplicate())
        assertEquals("hello", dtlsServer.handleAndDecrypt(record.duplicate()))
        dtlsServer.closeSessions()
        assertEquals(1, sessionStore.size())
        return clientSession to record
    }

    private fun DtlsServer.handleAndDecrypt(dtlsPacket: ByteBuffer): String {
        val receiveResult = this.handleReceived(localAddress(2_5684), dtlsPacket)
        return (receiveResult as ReceiveResult.Decrypted).packet.buffer.decodeToString()
    }
    private class InvalidCidSupplier(private val size: Int) : CidSupplier {
        override fun next(): ByteArray = Random.nextBytes(size)
        override fun isValidCid(cid: ByteArray): Boolean = false
    }
}
