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
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.opencoap.ssl.CertificateAuth
import org.opencoap.ssl.CertificateAuth.Companion.trusted
import org.opencoap.ssl.RandomCidSupplier
import org.opencoap.ssl.SslConfig
import org.opencoap.ssl.util.await
import org.opencoap.ssl.util.localAddress
import org.opencoap.ssl.util.runGC
import org.slf4j.LoggerFactory
import java.nio.ByteBuffer
import java.time.Duration
import java.util.concurrent.CompletableFuture
import java.util.concurrent.CompletableFuture.completedFuture

class DtlsTransmitterCertTest {

    private lateinit var srvTrans: Transport<ByteBuffer>
    private val randomCid = RandomCidSupplier(16)
    private var serverConf = SslConfig.server(CertificateAuth(Certs.serverChain, Certs.server.privateKey, Certs.root.asX509()))

    @AfterEach
    fun after() {
        srvTrans.close()
    }

    private fun newServerDtlsTransmitter(destLocalPort: Int): CompletableFuture<DtlsTransmitter> {
        srvTrans = DatagramChannelAdapter.connect(localAddress(destLocalPort), 0)
        return DtlsTransmitter.connect(localAddress(destLocalPort), serverConf, srvTrans)
    }

    @Test
    fun `should successfully handshake and send data`() {
        val server = newServerDtlsTransmitter(7001)

        val clientConf = SslConfig.client(CertificateAuth(Certs.dev01Chain, Certs.dev01.privateKey, Certs.root.asX509()))
        val client = DtlsTransmitter.connect(srvTrans, clientConf, 7001).await()

        runGC() // make sure none of needed objects is garbage collected
        client.send("dupa")
        assertEquals("dupa", server.join().receiveString())
        assertNotNull(client.cipherSuite)
        assertEquals("C=FI,O=Acme,CN=server", client.peerCertificateSubject)
    }

    @Test
    fun `should fail when non trusted`() {
        val server = newServerDtlsTransmitter(7002)

        val clientConf = SslConfig.client(CertificateAuth(Certs.dev99Chain, Certs.dev99.privateKey, Certs.root.asX509()))
        val client = DtlsTransmitter.connect(srvTrans, clientConf, 7002)

        assertTrue(
            runCatching { client.await() }
                .exceptionOrNull()?.cause?.message?.startsWith("SSL - A fatal alert message was received from our peer") == true
        )
    }

    @Test
    fun `should successfully handshake with server only cert`() {
        serverConf = SslConfig.server(CertificateAuth(Certs.serverChain, Certs.server.privateKey), reqAuthentication = false, cidSupplier = randomCid, cipherSuites = listOf("TLS-ECDHE-ECDSA-WITH-AES-128-GCM-SHA256"))
        runGC()

        val server = newServerDtlsTransmitter(7003)

        val clientConf = SslConfig.client(trusted(Certs.root.asX509()), cipherSuites = listOf("TLS-ECDHE-ECDSA-WITH-AES-128-GCM-SHA256"))
        val client = DtlsTransmitter.connect(srvTrans, clientConf, 7003).await()

        client.send("dupa")
        assertEquals("dupa", server.await().receiveString())
    }

    @Test
    fun `should successfully handshake with server's long chain of certs`() {
        serverConf = SslConfig.server(CertificateAuth(Certs.serverLongChain, Certs.server2.privateKey), reqAuthentication = false, cidSupplier = randomCid, mtu = 1024)
        val server = newServerDtlsTransmitter(7004)

        val clientConf = SslConfig.client(trusted(Certs.rootRsa.asX509()), cipherSuites = listOf("TLS-ECDHE-RSA-WITH-AES-128-GCM-SHA256"))
        val client = DtlsTransmitter.connect(srvTrans, clientConf, 7004).await()

        client.send("dupa")
        assertEquals("dupa", server.await().receiveString())

        assertTrue(client.saveSession().isNotEmpty())
    }

    @Test
    fun `should successfully handshake with server's leaf cert only`() {
        serverConf = SslConfig.server(CertificateAuth(listOf(Certs.server2.asX509()), Certs.server2.privateKey), reqAuthentication = false, cidSupplier = randomCid)
        val server = newServerDtlsTransmitter(7005)

        val clientConf = SslConfig.client(trusted(Certs.int2.asX509()), cipherSuites = listOf("TLS-ECDHE-ECDSA-WITH-AES-256-CBC-SHA384", "TLS-ECDHE-RSA-WITH-AES-128-CBC-SHA256"))
        val client = DtlsTransmitter.connect(srvTrans, clientConf, 7005).await()

        client.send("dupa")
        assertEquals("dupa", server.await().receiveString())
    }

    @Test
    fun `should fail handshake client does not trust server`() {
        serverConf = SslConfig.server(CertificateAuth(listOf(Certs.server2.asX509()), Certs.server2.privateKey), reqAuthentication = false)
        val server = newServerDtlsTransmitter(7006)

        val clientConf = SslConfig.client(trusted(Certs.int1a.asX509()))
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
            CertificateAuth(Certs.dev01Chain, Certs.dev01.privateKey, Certs.root.asX509()),
            retransmitMin = Duration.ofMillis(10),
            retransmitMax = Duration.ofMillis(100)
        )
        val cli = DatagramChannelAdapter
            .connect(srvTrans.localAddress(), 7007)
            .dropSend { it % 3 != 2 }

        // when
        val sslSession = DtlsTransmitter.connect(srvTrans.localAddress(), clientConf, cli).await()

        // then
        sslSession.close()
        clientConf.close()
        cli.close()
    }

    @Test
    fun `should timout handshake`() {
        newServerDtlsTransmitter(7008)

        val clientConf = SslConfig.client(
            CertificateAuth(Certs.dev01Chain, Certs.dev01.privateKey, Certs.root.asX509()),
            retransmitMin = Duration.ofMillis(10),
            retransmitMax = Duration.ofMillis(100)
        )
        val cli = DatagramChannelAdapter
            .connect(srvTrans.localAddress(), 7008)
            .dropSend { true }

        // when
        val res = runCatching { DtlsTransmitter.connect(srvTrans.localAddress(), clientConf, cli).await() }

        // then
        assertEquals("SSL - The operation timed out [-0x6800]", res.exceptionOrNull()?.cause?.message)
        clientConf.close()
        cli.close()
    }
}

internal fun <P> Transport<P>.dropSend(drop: (Int) -> Boolean): Transport<P> {
    val underlying = this
    var i = 0

    return object : Transport<P> by this {
        private val logger = LoggerFactory.getLogger(javaClass)

        override fun send(packet: P): CompletableFuture<Boolean> {
            return if (!drop(i++)) {
                underlying.send(packet)
            } else {
                logger.info("send DROPPED {}", packet)
                completedFuture(true)
            }
        }
    }
}
