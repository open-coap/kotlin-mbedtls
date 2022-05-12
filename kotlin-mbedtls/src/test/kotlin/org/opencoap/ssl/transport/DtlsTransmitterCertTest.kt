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
import java.net.InetSocketAddress
import java.nio.channels.DatagramChannel

class DtlsTransmitterCertTest {

    private val serverChannel = DatagramChannel.open().bind(localAddress(0))
    private val randomCid = RandomCidSupplier(16)
    private val serverAdr = serverChannel.localAddress as InetSocketAddress
    private val serverConf = SslConfig.server(Certs.serverChain, Certs.server.privateKey, listOf(Certs.root.asX509()))

    @AfterEach
    fun after() {
        serverChannel.close()
    }

    @Test
    fun `should successfully handshake and send data`() {
        val server = DtlsTransmitter.connect(localAddress(7001), serverConf, serverChannel)

        val clientConf = SslConfig.client(Certs.dev01Chain, Certs.dev01.privateKey, listOf(Certs.root.asX509()))
        val client = DtlsTransmitter.connect(serverAdr, clientConf, 7001).await()

        runGC() // make sure none of needed objects is garbage collected
        client.send("dupa")
        assertEquals("dupa", server.join().receiveString())
        assertNotNull(client.getCipherSuite())
    }

    @Test
    fun `should fail when non trusted`() {
        val server = DtlsTransmitter.connect(localAddress(7002), serverConf, serverChannel)

        val clientConf = SslConfig.client(Certs.dev99Chain, Certs.dev99.privateKey, listOf(Certs.root.asX509()))
        val client = DtlsTransmitter.connect(serverAdr, clientConf, 7002)

        assertTrue(
            runCatching { client.await() }
                .exceptionOrNull()?.cause?.message?.startsWith("SSL - A fatal alert message was received from our peer") == true
        )
    }

    @Test
    fun `should successfully handshake with server only cert`() {
        val serverConf = SslConfig.server(Certs.serverChain, Certs.server.privateKey, reqAuthentication = false, cidSupplier = randomCid)
        val server = DtlsTransmitter.connect(localAddress(7003), serverConf, serverChannel)

        val clientConf = SslConfig.client(trustedCerts = listOf(Certs.root.asX509()), cipherSuites = listOf("TLS-ECDHE-ECDSA-WITH-AES-256-CBC-SHA384", "TLS-ECDHE-RSA-WITH-AES-128-CBC-SHA256"))
        val client = DtlsTransmitter.connect(serverAdr, clientConf, 7003).await()

        client.send("dupa")
        assertEquals("dupa", server.await().receiveString())
    }

    @Test
    fun `should successfully handshake with server's long chain of certs`() {
        val serverConf = SslConfig.server(Certs.serverLongChain, Certs.server2.privateKey, reqAuthentication = false, cidSupplier = randomCid, mtu = 1024)
        val server = DtlsTransmitter.connect(localAddress(7004), serverConf, serverChannel)

        val clientConf = SslConfig.client(trustedCerts = listOf(Certs.rootRsa.asX509()), cipherSuites = listOf("TLS-ECDHE-ECDSA-WITH-AES-256-CBC-SHA384", "TLS-ECDHE-RSA-WITH-AES-128-CBC-SHA256"))
        val client = DtlsTransmitter.connect(serverAdr, clientConf, 7004).await()

        client.send("dupa")
        assertEquals("dupa", server.await().receiveString())
    }

    @Test
    fun `should successfully handshake with server's leaf cert only`() {
        val serverConf = SslConfig.server(listOf(Certs.server2.asX509()), Certs.server2.privateKey, reqAuthentication = false, cidSupplier = randomCid)
        val server = DtlsTransmitter.connect(localAddress(7005), serverConf, serverChannel)

        val clientConf = SslConfig.client(trustedCerts = listOf(Certs.int2.asX509()), cipherSuites = listOf("TLS-ECDHE-ECDSA-WITH-AES-256-CBC-SHA384", "TLS-ECDHE-RSA-WITH-AES-128-CBC-SHA256"))
        val client = DtlsTransmitter.connect(serverAdr, clientConf, 7005).await()

        client.send("dupa")
        assertEquals("dupa", server.await().receiveString())
    }

    @Test
    fun `should fail handshake client does not trust server`() {
        val serverConf = SslConfig.server(listOf(Certs.server2.asX509()), Certs.server2.privateKey, reqAuthentication = false)
        val server = DtlsTransmitter.connect(localAddress(7006), serverConf, serverChannel)

        val clientConf = SslConfig.client(trustedCerts = listOf(Certs.int1a.asX509()))
        val client = DtlsTransmitter.connect(serverAdr, clientConf, 7006)

        assertTrue(
            runCatching { client.await() }
                .exceptionOrNull()?.cause?.message?.startsWith("X509 - Certificate verification failed, e.g. CRL, CA or signature check failed") == true
        )
        await.untilAsserted { assertTrue(server.isCompletedExceptionally) }
    }
}
