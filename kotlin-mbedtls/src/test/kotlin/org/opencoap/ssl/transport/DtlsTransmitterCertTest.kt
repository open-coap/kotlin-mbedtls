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
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.opencoap.ssl.RandomCidSupplier
import org.opencoap.ssl.SslConfig
import org.opencoap.ssl.util.await
import org.opencoap.ssl.util.localAddress
import org.opencoap.ssl.util.runGC
import org.slf4j.LoggerFactory
import java.nio.ByteBuffer
import java.time.Duration
import java.util.concurrent.CompletableFuture

class DtlsTransmitterCertTest {

    private lateinit var srvTrans: ConnectedDatagramTransmitter
    private val randomCid = RandomCidSupplier(16)
    private var serverConf = SslConfig.server(Certs.serverChain, Certs.server.privateKey, listOf(Certs.root.asX509()))
    private val logger = LoggerFactory.getLogger(javaClass)

    @AfterEach
    fun after() {
        srvTrans.close()
    }

    private fun newServerDtlsTransmitter(destLocalPort: Int): CompletableFuture<DtlsTransmitter> {
        srvTrans = ConnectedDatagramTransmitter.connect(localAddress(destLocalPort), 0)
        return DtlsTransmitter.connect(serverConf, srvTrans)
    }

    @Test
    fun `should successfully handshake and send data`() {
        val server = newServerDtlsTransmitter(7001)

        val clientConf = SslConfig.client(Certs.dev01Chain, Certs.dev01.privateKey, listOf(Certs.root.asX509()))
        val client = DtlsTransmitter.connect(srvTrans, clientConf, 7001).await()

        runGC() // make sure none of needed objects is garbage collected
        client.send("dupa")
        assertEquals("dupa", server.join().receiveString())
        assertNotNull(client.getCipherSuite())
    }

    @Test
    fun `should fail when non trusted`() {
        val server = newServerDtlsTransmitter(7002)

        val clientConf = SslConfig.client(Certs.dev99Chain, Certs.dev99.privateKey, listOf(Certs.root.asX509()))
        val client = DtlsTransmitter.connect(srvTrans, clientConf, 7002)

        assertTrue(
            runCatching { client.await() }
                .exceptionOrNull()?.cause?.message?.startsWith("SSL - A fatal alert message was received from our peer") == true
        )
    }

    @Test
    fun `should successfully handshake with server only cert`() {
        serverConf = SslConfig.server(Certs.serverChain, Certs.server.privateKey, reqAuthentication = false, cidSupplier = randomCid)
        val server = newServerDtlsTransmitter(7003)

        val clientConf = SslConfig.client(trustedCerts = listOf(Certs.root.asX509()), cipherSuites = listOf("TLS-ECDHE-ECDSA-WITH-AES-256-CBC-SHA384", "TLS-ECDHE-RSA-WITH-AES-128-CBC-SHA256"))
        val client = DtlsTransmitter.connect(srvTrans, clientConf, 7003).await()

        client.send("dupa")
        assertEquals("dupa", server.await().receiveString())
    }

    @Test
    fun `should successfully handshake with server's long chain of certs`() {
        serverConf = SslConfig.server(Certs.serverLongChain, Certs.server2.privateKey, reqAuthentication = false, cidSupplier = randomCid, mtu = 1024)
        val server = newServerDtlsTransmitter(7004)

        val clientConf = SslConfig.client(trustedCerts = listOf(Certs.rootRsa.asX509()), cipherSuites = listOf("TLS-ECDHE-ECDSA-WITH-AES-256-CBC-SHA384", "TLS-ECDHE-RSA-WITH-AES-128-CBC-SHA256"))
        val client = DtlsTransmitter.connect(srvTrans, clientConf, 7004).await()

        client.send("dupa")
        assertEquals("dupa", server.await().receiveString())
    }

    @Test
    fun `should successfully handshake with server's leaf cert only`() {
        serverConf = SslConfig.server(listOf(Certs.server2.asX509()), Certs.server2.privateKey, reqAuthentication = false, cidSupplier = randomCid)
        val server = newServerDtlsTransmitter(7005)

        val clientConf = SslConfig.client(trustedCerts = listOf(Certs.int2.asX509()), cipherSuites = listOf("TLS-ECDHE-ECDSA-WITH-AES-256-CBC-SHA384", "TLS-ECDHE-RSA-WITH-AES-128-CBC-SHA256"))
        val client = DtlsTransmitter.connect(srvTrans, clientConf, 7005).await()

        client.send("dupa")
        assertEquals("dupa", server.await().receiveString())
    }

    @Test
    fun `should fail handshake client does not trust server`() {
        serverConf = SslConfig.server(listOf(Certs.server2.asX509()), Certs.server2.privateKey, reqAuthentication = false)
        val server = newServerDtlsTransmitter(7006)

        val clientConf = SslConfig.client(trustedCerts = listOf(Certs.int1a.asX509()))
        val client = DtlsTransmitter.connect(srvTrans, clientConf, 7006)

        assertTrue(
            runCatching { client.await() }
                .exceptionOrNull()?.cause?.message?.startsWith("X509 - Certificate verification failed, e.g. CRL, CA or signature check failed") == true
        )
        await.untilAsserted { assertTrue(server.isCompletedExceptionally) }
    }

    @Test
    fun `should successfully handshake with retransmission`() {
        val server = newServerDtlsTransmitter(7007)

        val clientConf = SslConfig.client(
            Certs.dev01Chain, Certs.dev01.privateKey, listOf(Certs.root.asX509()),
            retransmitMin = Duration.ofMillis(10),
            retransmitMax = Duration.ofMillis(100)
        )
        val cli: ConnectedDatagramTransmitter = ConnectedDatagramTransmitter
            .connect(srvTrans.localAddress(), 7007)
            .dropSend { it % 3 != 2 }

        // when
        val sslSession = DtlsTransmitter.handshake(clientConf.newContext(), cli::send, cli::receive)

        // then
        sslSession.close()
        clientConf.close()
        cli.close()
    }

    @Test
    fun `should timout handshake`() {
        newServerDtlsTransmitter(7008)

        val clientConf = SslConfig.client(
            Certs.dev01Chain, Certs.dev01.privateKey, listOf(Certs.root.asX509()),
            retransmitMin = Duration.ofMillis(10),
            retransmitMax = Duration.ofMillis(100)
        )
        val cli: ConnectedDatagramTransmitter = ConnectedDatagramTransmitter
            .connect(srvTrans.localAddress(), 7008)
            .dropSend { true }

        // when
        val res = runCatching { DtlsTransmitter.handshake(clientConf.newContext(), cli::send, cli::receive) }

        // then
        assertEquals("SSL - The operation timed out [-26624]", res.exceptionOrNull()?.message)
        clientConf.close()
        cli.close()
    }
}

internal fun ConnectedDatagramTransmitter.dropSend(drop: (Int) -> Boolean): ConnectedDatagramTransmitter {
    val underlying = this
    var i = 0

    return object : ConnectedDatagramTransmitter by this {
        private val logger = LoggerFactory.getLogger(javaClass)

        override fun send(buf: ByteBuffer) {
            if (!drop(i++)) {
                underlying.send(buf)
            } else {
                logger.info("send DROPPED {}", buf.remaining())
            }
        }
    }
}
