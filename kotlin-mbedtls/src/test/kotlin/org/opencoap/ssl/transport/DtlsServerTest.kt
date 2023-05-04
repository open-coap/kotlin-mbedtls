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

import org.junit.jupiter.api.AfterAll
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestInstance
import org.opencoap.ssl.CertificateAuth
import org.opencoap.ssl.RandomCidSupplier
import org.opencoap.ssl.SslConfig
import org.opencoap.ssl.util.Certs
import org.opencoap.ssl.util.StoredSessionPair
import org.opencoap.ssl.util.await
import org.opencoap.ssl.util.decodeHex
import org.opencoap.ssl.util.localAddress
import java.nio.ByteOrder
import java.util.concurrent.CompletableFuture.completedFuture

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class DtlsServerTest {
    val serverConf = SslConfig.server(CertificateAuth(Certs.serverChain, Certs.server.privateKey), listOf("TLS-ECDHE-ECDSA-WITH-AES-128-GCM-SHA256"), false, RandomCidSupplier(16))
    val clientConf = SslConfig.client(CertificateAuth.trusted(Certs.root.asX509()), cipherSuites = listOf("TLS-ECDHE-ECDSA-WITH-AES-128-GCM-SHA256"))

    private val sessionStore = HashMapSessionStore()
    private lateinit var dtlsServer: DtlsServer

    @BeforeEach
    fun setUp() {
        dtlsServer = DtlsServer({ completedFuture(true) }, serverConf, sessionStore = sessionStore, executor = SingleThreadExecutor.create("dtls-srv-"))
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
        sessionStore.write("f935adc57425e1b214f8640d56e0c733".decodeHex(), SessionWithContext(StoredSessionPair.srvSession, mapOf()))
        val clientSession = clientConf.loadSession(byteArrayOf(), StoredSessionPair.cliSession, localAddress(2_5684))

        // when
        val dtlsPacket = clientSession.encrypt("hello".toByteBuffer()).order(ByteOrder.BIG_ENDIAN)
        assertEquals("hello", dtlsServer.handleReceived(localAddress(2_5684), dtlsPacket).await().buffer.decodeToString())

        val dtlsPacket2 = dtlsServer.encrypt("hello2".toByteBuffer(), localAddress(2_5684))!!.order(ByteOrder.BIG_ENDIAN)
        assertEquals("hello2", clientSession.decrypt(dtlsPacket2).decodeToString())

        clientSession.close()
    }

    @Test
    fun `should ignore when session not found in store`() {
        sessionStore.clear()
        val clientSession = clientConf.loadSession(byteArrayOf(), StoredSessionPair.cliSession, localAddress(2_5684))

        val dtlsPacket = clientSession.encrypt("hello".toByteBuffer()).order(ByteOrder.BIG_ENDIAN)
        assertEquals(Packet.EmptyByteBufferPacket, dtlsServer.handleReceived(localAddress(2_5684), dtlsPacket).await())

        clientSession.close()
    }
}
