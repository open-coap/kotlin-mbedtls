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

import org.awaitility.kotlin.await
import org.junit.jupiter.api.AfterAll
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestInstance
import org.opencoap.ssl.CertificateAuth
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
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.time.Instant
import java.util.LinkedList
import java.util.concurrent.CompletableFuture
import java.util.concurrent.CompletableFuture.completedFuture

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class DtlsServerTest {
    val serverConf = SslConfig.server(CertificateAuth(Certs.serverChain, Certs.server.privateKey), listOf("TLS-ECDHE-ECDSA-WITH-AES-128-GCM-SHA256"), false, RandomCidSupplier(16))
    val clientConf = SslConfig.client(CertificateAuth.trusted(Certs.root.asX509()), cipherSuites = listOf("TLS-ECDHE-ECDSA-WITH-AES-128-GCM-SHA256"))

    private val sessionStore = HashMapSessionStore()
    private lateinit var dtlsServer: DtlsServer
    private val serverOutboundQueue = LinkedList<ByteBuffer>()

    @BeforeEach
    fun setUp() {
        dtlsServer = DtlsServer(::outboundTransport, serverConf, 100.millis, sessionStore::write, executor = SingleThreadExecutor.create("dtls-srv-"))
    }

    private fun outboundTransport(it: ByteBufferPacket): CompletableFuture<Boolean> {
        serverOutboundQueue.add(it.buffer.copy())
        return completedFuture(true)
    }

    @AfterEach
    fun tearDown() {
        dtlsServer.closeSessions()
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
        dtlsServer.loadSession(SessionWithContext(StoredSessionPair.srvSession, mapOf(), Instant.ofEpochSecond(123456789)), localAddress(2_5684), "f935adc57425e1b214f8640d56e0c733".decodeHex())

        // then
        val dtlsPacketIn = (dtlsServer.handleReceived(localAddress(2_5684), dtlsPacket) as ReceiveResult.Decrypted).packet
        assertEquals("hello", dtlsPacketIn.buffer.decodeToString())
        assertEquals(Instant.ofEpochSecond(123456789), dtlsPacketIn.sessionContext.sessionStartTimestamp)
        val dtlsPacketOut = dtlsServer.encrypt("hello2".toByteBuffer(), localAddress(2_5684))!!.order(ByteOrder.BIG_ENDIAN)
        assertEquals("hello2", clientSession.decrypt(dtlsPacketOut, noSend).decodeToString())

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
    fun `should handshake`() {
        // when
        val clientSession = clientHandshake()

        // then
        val dtlsPacket = clientSession.encrypt("terve".toByteBuffer()).order(ByteOrder.BIG_ENDIAN)
        val dtlsPacketIn = (dtlsServer.handleReceived(localAddress(2_5684), dtlsPacket) as ReceiveResult.Decrypted).packet
        assertEquals("terve", dtlsPacketIn.buffer.decodeToString())
//        assertTrue(Instant.now().isAfter(dtlsPacketIn.sessionContext.sessionStartTimestamp!!))

        assertEquals(1, dtlsServer.numberOfSessions)

        await.untilAsserted {
            assertTrue(serverOutboundQueue.isEmpty())
        }

        clientSession.close()
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
        serverOutboundQueue.remove(); cliHandshake.step(Packet.EMPTY_BYTEBUFFER, send)

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
        serverOutboundQueue.remove(); cliHandshake.step(Packet.EMPTY_BYTEBUFFER, send)

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

    private fun clientHandshake(): SslSession {
        val send: (ByteBuffer) -> Unit = { dtlsServer.handleReceived(localAddress(2_5684), it) }
        val cliHandshake = clientConf.newContext(localAddress(5684))

        cliHandshake.step(send)
        cliHandshake.step(serverOutboundQueue.remove(), send)
        cliHandshake.step(serverOutboundQueue.remove(), send)
        return cliHandshake.step(serverOutboundQueue.remove(), send) as SslSession
    }

    private val noSend: (ByteBuffer) -> Unit = { throw IllegalStateException() }

    private fun DtlsServer.handleAndDecrypt(dtlsPacket: ByteBuffer): String {
        val receiveResult = this.handleReceived(localAddress(2_5684), dtlsPacket)
        return (receiveResult as ReceiveResult.Decrypted).packet.buffer.decodeToString()
    }
}
