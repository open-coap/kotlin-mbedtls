/*
 * Copyright (c) 2026 kotlin-mbedtls contributors (https://github.com/open-coap/kotlin-mbedtls)
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

import io.netty.channel.socket.DatagramChannel
import org.awaitility.kotlin.await
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.opencoap.ssl.CertificateAuth
import org.opencoap.ssl.RandomCidSupplier
import org.opencoap.ssl.SslConfig
import org.opencoap.ssl.netty.NettyHelpers.createBootstrap
import org.opencoap.ssl.transport.CID
import org.opencoap.ssl.transport.HashMapSessionStore
import org.opencoap.ssl.transport.SessionStore
import org.opencoap.ssl.transport.SessionWithContext
import org.opencoap.ssl.transport.SessionWriter
import org.opencoap.ssl.util.Certs
import org.opencoap.ssl.util.StoredSessionPair
import org.opencoap.ssl.util.await
import org.opencoap.ssl.util.localAddress
import org.opencoap.ssl.util.seconds
import java.net.InetSocketAddress
import java.time.Instant
import java.util.concurrent.CompletableFuture
import java.util.concurrent.CopyOnWriteArrayList

class NettyShutdownTest {

    private val serverConf = SslConfig.server(CertificateAuth(Certs.serverChain, Certs.server.privateKey), listOf("TLS-ECDHE-ECDSA-WITH-AES-128-GCM-SHA256"), false, cidSupplier = RandomCidSupplier(16))
    private val clientConf = SslConfig.client(CertificateAuth.trusted(Certs.root.asX509()))
    private val sessionStore = HashMapSessionStore()

    @AfterEach
    fun tearDown() {
        sessionStore.clear()
        serverConf.close()
    }

    @Test
    fun `should store active session when channel is closed`() {
        // given, a session that is in active use (never idle long enough to be stored by timeout)
        val srvChannel = createBootstrap(0, DtlsChannelHandler(serverConf, sessionStore = sessionStore), { addLast("echo", EchoHandler()) }).bind().sync().channel() as DatagramChannel
        val srvAddress: InetSocketAddress = localAddress(srvChannel.localAddress().port)
        val client = NettyTransportAdapter.connect(clientConf, srvAddress).mapToString()

        assertTrue(client.send("hi").await())
        assertEquals("ECHO:hi", client.receive(5.seconds).await())

        // when
        srvChannel.close().sync()

        // then, the session was handed over to the shared store
        assertEquals(1, sessionStore.size())

        client.close()
    }

    @Test
    fun `should resume flushed session on a replacement server`() {
        // given, a session that is in active use
        val srvChannel = createBootstrap(0, DtlsChannelHandler(serverConf, sessionStore = sessionStore), { addLast("echo", EchoHandler()) }).bind().sync().channel() as DatagramChannel
        val port = srvChannel.localAddress().port
        val srvAddress: InetSocketAddress = localAddress(port)
        val client = NettyTransportAdapter.connect(clientConf, srvAddress).mapToString()

        assertTrue(client.send("hi").await())
        assertEquals("ECHO:hi", client.receive(5.seconds).await())

        // when, the pod is replaced: the old server closes and a fresh one takes over the same address
        srvChannel.close().sync()
        val replacementChannel = createBootstrap(port, DtlsChannelHandler(serverConf, sessionStore = sessionStore), { addLast("echo", EchoHandler()) }).bind().sync().channel() as DatagramChannel

        // then, the device keeps using the same CID and is still served
        assertTrue(client.send("hi again").await())
        assertEquals("ECHO:hi again", client.receive(5.seconds).await())

        client.close()
        replacementChannel.close().sync()
    }

    @Test
    fun `should store back session read that was pending when channel was closed`() {
        // given, a device's session is being read from the store
        val pendingStore = PendingReadSessionStore()
        val handler = DtlsChannelHandler(serverConf, sessionStore = pendingStore)
        val srvChannel = createBootstrap(0, handler, { addLast("echo", EchoHandler()) }).bind().sync().channel() as DatagramChannel
        val client = reloadedClient(srvChannel)
        client.send("Terve").await()
        await.atMost(5.seconds).until { pendingStore.reads.size == 1 }

        // when
        assertTrue(srvChannel.close().await(5000))
        pendingStore.reads[0].complete(storedSession())

        // then, the session is not loaded, it is stored back
        srvChannel.eventLoop().submit {}.await()
        assertEquals(0, srvChannel.eventLoop().submit<Int> { handler.dtlsServer.numberOfSessions }.get())
        assertEquals(listOf(StoredSessionPair.cid.toList()), pendingStore.writes.map(CID::toList))

        client.close()
    }

    private fun reloadedClient(srvChannel: DatagramChannel) = NettyTransportAdapter.reload(
        clientConf.loadSession(byteArrayOf(), StoredSessionPair.cliSession, localAddress(srvChannel.localAddress().port)),
        localAddress(srvChannel.localAddress().port),
        SessionWriter.NO_OPS
    ).mapToString()

    private fun storedSession() = SessionWithContext(StoredSessionPair.srvSession, mapOf(), Instant.ofEpochSecond(123456789))

    private class PendingReadSessionStore : SessionStore {
        val reads = CopyOnWriteArrayList<CompletableFuture<SessionWithContext?>>()
        val writes = CopyOnWriteArrayList<CID>()

        override fun read(cid: CID): CompletableFuture<SessionWithContext?> = CompletableFuture<SessionWithContext?>().also(reads::add)

        override fun write(cid: CID, session: SessionWithContext) {
            writes.add(cid)
        }
    }
}
