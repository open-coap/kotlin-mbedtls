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

package org.opencoap.ssl.netty

import io.mockk.mockk
import io.mockk.verify
import io.netty.channel.ChannelHandlerContext
import io.netty.channel.ChannelInboundHandlerAdapter
import io.netty.channel.nio.NioEventLoopGroup
import io.netty.channel.socket.DatagramChannel
import io.netty.channel.socket.DatagramPacket
import io.netty.util.concurrent.DefaultThreadFactory
import org.assertj.core.api.Assertions.assertThatThrownBy
import org.awaitility.kotlin.await
import org.junit.jupiter.api.AfterAll
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestInstance
import org.opencoap.ssl.CertificateAuth
import org.opencoap.ssl.EmptyCidSupplier
import org.opencoap.ssl.PskAuth
import org.opencoap.ssl.RandomCidSupplier
import org.opencoap.ssl.SslConfig
import org.opencoap.ssl.SslException
import org.opencoap.ssl.netty.NettyHelpers.createBootstrap
import org.opencoap.ssl.transport.DtlsServer
import org.opencoap.ssl.transport.DtlsSessionContext
import org.opencoap.ssl.transport.HashMapSessionStore
import org.opencoap.ssl.transport.SessionWithContext
import org.opencoap.ssl.transport.SessionWriter
import org.opencoap.ssl.transport.Transport
import org.opencoap.ssl.util.Certs
import org.opencoap.ssl.util.StoredSessionPair
import org.opencoap.ssl.util.await
import org.opencoap.ssl.util.localAddress
import org.opencoap.ssl.util.seconds
import java.net.InetSocketAddress
import java.nio.channels.ClosedChannelException
import java.nio.charset.Charset
import java.time.Instant
import java.util.concurrent.ExecutionException
import java.util.concurrent.TimeUnit
import kotlin.random.Random

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class NettyTest {

    private val serverConf = SslConfig.server(CertificateAuth(Certs.serverChain, Certs.server.privateKey), listOf("TLS-ECDHE-ECDSA-WITH-AES-128-GCM-SHA256"), false, cidSupplier = RandomCidSupplier(16))
    private val clientConf = SslConfig.client(CertificateAuth.trusted(Certs.root.asX509()))
    private lateinit var srvChannel: DatagramChannel
    private val srvAddress: InetSocketAddress by lazy { localAddress(srvChannel.localAddress().port) }
    private val dtlsServer: DtlsServer by lazy { (srvChannel.pipeline().get("DTLS") as DtlsChannelHandler).dtlsServer }
    private val sessionStore = HashMapSessionStore()

    @BeforeAll
    fun beforeAll() {
        srvChannel = createBootstrap(0, DtlsChannelHandler(serverConf, sessionStore = sessionStore), { addLast("echo", EchoHandler()) }).bind().sync().channel() as DatagramChannel
    }

    @AfterAll
    fun afterAll() {
        srvChannel.close().sync()
        serverConf.close()
    }

    @AfterEach
    fun tearDown() {
        // close all sessions
        srvChannel.eventLoop().submit {
            dtlsServer.closeSessions()
        }.await()

        sessionStore.clear()
    }

    @Test
    fun testSingleConnection() {
        // connect and handshake
        val client = NettyTransportAdapter.connect(clientConf, srvAddress).mapToString()

        assertTrue(client.send("hi").await())
        assertEquals("ECHO:hi", client.receive(5.seconds).await())

        assertTrue(client.send("hi5").await())
        assertEquals("ECHO:hi5", client.receive(5.seconds).await())

        client.close()
    }

    @Test
    fun testSingleConnection_directMemory() {
        // connect and handshake
        val client = NettyTransportAdapter.connect(clientConf, srvAddress)

        val buf = client.channel.alloc().directBuffer().writeString("hi")
        assertTrue(client.send(buf).await())
        assertEquals("ECHO:hi", client.receive(5.seconds).await().toString(Charset.defaultCharset()))

        val buf2 = client.channel.alloc().directBuffer().writeString("hi5")
        assertTrue(client.send(buf2).await())
        assertEquals("ECHO:hi5", client.receive(5.seconds).await().toString(Charset.defaultCharset()))

        client.close()
    }

    @Test
    fun `ignore malformed packet`() {
        // given, connected and handshake done
        val client = NettyTransportAdapter.connect(clientConf, srvAddress)
        val textClient = client.mapToString()

        assertTrue(textClient.send("hi").await())
        assertEquals("ECHO:hi", textClient.receive(5.seconds).await())

        // when
        client.channel.channelRead(DatagramPacket(Random.nextBytes(42).toByteBuf(), null, srvAddress))
        srvChannel.channelRead(DatagramPacket(Random.nextBytes(42).toByteBuf(), null, srvAddress))

        // then, still working
        assertTrue(textClient.send("hi5").await())
        assertEquals("ECHO:hi5", textClient.receive(5.seconds).await())

        client.close()
    }

    @Test
    fun testFailedHandshake() {
        val clientConfig2 = SslConfig.client(PskAuth("wrong", byteArrayOf(1)), cidSupplier = EmptyCidSupplier)

        // when
        val client = NettyTransportAdapter.connect(clientConfig2, srvAddress).mapToString()

        // then
        assertThatThrownBy { client.send("hi").await() }.isInstanceOf(ExecutionException::class.java).hasCauseInstanceOf(ClosedChannelException::class.java)
        assertThatThrownBy { client.send("hi").await() }.hasCauseInstanceOf(ClosedChannelException::class.java)

        client.close()
        clientConfig2.close()
        assertEquals(0, dtlsServer.numberOfSessions)
    }

    @Test
    fun testMultipleConnections() {
        val max = 20
        val eventLoopGroup = NioEventLoopGroup(1, DefaultThreadFactory("udp", true))

        val clients = (1..max)
            .map {
                NettyTransportAdapter.connect(clientConf, srvAddress, eventLoopGroup).mapToString()
            }

        clients.forEach { client ->
            val i = Random.nextInt()
            client.send("dupa$i")
            assertEquals("ECHO:dupa$i", client.receive(5.seconds).await())
        }

        assertEquals(max, dtlsServer.numberOfSessions)
        clients.forEach(Transport<String>::close)
    }

    @Test
    fun `should forward authentication context`() {
        // connect and handshake
        val client = NettyTransportAdapter.connect(clientConf, srvAddress).mapToString()

        assertTrue(client.send("hi").await())
        assertEquals("ECHO:hi", client.receive(5.seconds).await())

        // when
        srvChannel.writeAndFlush(SessionAuthenticationContext(client.localAddress(), mapOf("AUTH" to "007:"))).get()

        // then
        assertTrue(client.send("hi").await())
        assertEquals("ECHO:007:hi", client.receive(5.seconds).await())

        client.close()
    }

    @Test
    fun `should fail to forward authentication context for non existing client`() {
        assertThatThrownBy {
            srvChannel.writeAndFlush(SessionAuthenticationContext(localAddress(1), mapOf("AUTH" to "007:"))).get()
        }.hasRootCause(SslException("Session does not exists"))
    }

    @Test
    fun `server should load session from store`() {
        sessionStore.write(StoredSessionPair.cid, SessionWithContext(StoredSessionPair.srvSession, mapOf(), Instant.ofEpochSecond(123456789)))
        val storeSessionMock: SessionWriter = mockk(relaxed = true)
        val client = NettyTransportAdapter.reload(clientConf.loadSession(byteArrayOf(), StoredSessionPair.cliSession, srvAddress), srvAddress, storeSessionMock).mapToString()

        client.send("Terve").await()
        assertEquals("ECHO:Terve", client.receive(2.seconds).await())

        client.close()
        verify { storeSessionMock.invoke(any(), any()) }
        assertEquals(1, dtlsServer.numberOfSessions)
    }

    @Test
    fun `server should ignore packet with missing session`() {
        // given
        // server's session store is empty
        sessionStore.clear()
        val client = NettyTransportAdapter.reload(clientConf.loadSession(byteArrayOf(), StoredSessionPair.cliSession, srvAddress), srvAddress, SessionWriter.NO_OPS).mapToString()

        // when
        client.send("Terve").await()

        // then
        assertEquals(0, dtlsServer.numberOfSessions)
        client.close()
    }

    @Test
    fun `server should store session if hinted to do so`() {
        val hintedSrvChannel = createBootstrap(
            0,
            DtlsChannelHandler(serverConf, sessionStore = sessionStore),
            {
                addLast("echo", object : ChannelInboundHandlerAdapter() {
                    override fun channelRead(ctx: ChannelHandlerContext, msg: Any) {
                        val dgram = msg as DatagramPacket
                        val dgramContent = dgram.content().toByteArray()
                        val dgramSender = dgram.sender()
                        val reply = ctx.alloc().buffer(dgram.content().readableBytes()).writeBytes(dgramContent)
                        val goToSleep = dgramContent.toString(Charset.defaultCharset()).endsWith(":sleep")

                        ctx.writeAndFlush(
                            DatagramPacketWithContext(
                                reply,
                                dgramSender,
                                null,
                                DtlsSessionContext(sessionExpirationHint = goToSleep)
                            )
                        )
                    }
                })
            }
        ).bind().sync().channel() as DatagramChannel

        val hintedDtlsServer = (hintedSrvChannel.pipeline().get("DTLS") as DtlsChannelHandler).dtlsServer
        val hintedSrvAddr = localAddress(hintedSrvChannel.localAddress().port)

        // connect and handshake
        val client = NettyTransportAdapter.connect(clientConf, hintedSrvAddr).mapToString()

        assertTrue(client.send("hi").await())
        assertEquals("hi", client.receive(5.seconds).await())

        assertEquals(1, hintedDtlsServer.numberOfSessions)
        assertEquals(0, sessionStore.size())

        assertTrue(client.send("hi:sleep").await())
        assertEquals("hi:sleep", client.receive(5.seconds).await())

        await.atMost(5.seconds).untilAsserted {
            assertEquals(0, hintedDtlsServer.numberOfSessions)
            assertEquals(1, sessionStore.size())
        }

        client.close()
    }

}
