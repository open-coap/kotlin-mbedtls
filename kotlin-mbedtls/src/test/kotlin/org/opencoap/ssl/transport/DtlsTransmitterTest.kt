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

import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.opencoap.ssl.SslConfig
import org.opencoap.ssl.util.await
import org.opencoap.ssl.util.decodeHex
import org.opencoap.ssl.util.localAddress
import org.opencoap.ssl.util.runGC
import java.time.Duration
import java.util.concurrent.CompletableFuture
import kotlin.random.Random

class DtlsTransmitterTest {

    private val cidSupplier = { Random.nextBytes(16) }
    private val serverConf = SslConfig.server("dupa".encodeToByteArray(), byteArrayOf(0x01, 0x02), cidSupplier = cidSupplier)
    private lateinit var srvTrans: ConnectedDatagramTransmitter

    @AfterEach
    fun after() {
        srvTrans.close()
        serverConf.close()
    }

    private fun newServerDtlsTransmitter(destLocalPort: Int): CompletableFuture<DtlsTransmitter> {
        srvTrans = ConnectedDatagramTransmitter.connect(localAddress(destLocalPort), 1_5684)
        return DtlsTransmitter.connect(serverConf, srvTrans)
    }

    @Test
    fun `should successfully handshake and send data`() {
        val server = newServerDtlsTransmitter(6001)
        val conf = SslConfig.client("dupa".encodeToByteArray(), byteArrayOf(0x01, 0x02))
        runGC() // make sure none of needed objects is garbage collected

        // when
        val client = DtlsTransmitter.connect(localAddress(1_5684), conf, 6001).await()
        runGC() // make sure none of needed objects is garbage collected

        // then
        client.send("dupa")
        assertEquals("dupa", server.await().receiveString())
        // and read with timeout
        assertTrue(client.receive(Duration.ofMillis(1)).isEmpty())

        assertNotNull(client.getCipherSuite())
        client.close()
        conf.close()
        server.await().close()
    }

    @Test
    fun `should fail to handshake - wrong psk`() {
        val server = newServerDtlsTransmitter(6002)

        val conf = SslConfig.client("dupa".encodeToByteArray(), "bad".encodeToByteArray())
        val client = DtlsTransmitter.connect(localAddress(1_5684), conf, 6002)

        val result = runCatching { client.await() }

        // then
        assertEquals(
            "SSL - A fatal alert message was received from our peer [-0x7780]",
            result.exceptionOrNull()?.cause?.message
        )
        conf.close()
    }

    @Test
    fun `should use CID`() {
        val server = newServerDtlsTransmitter(6003)

        val conf = SslConfig.client(
            pskId = "dupa".encodeToByteArray(),
            pskSecret = byteArrayOf(0x01, 0x02),
            cidSupplier = { byteArrayOf(0x01) },
            cipherSuites = listOf("TLS-PSK-WITH-AES-128-CCM"),
        )

        // when
        val client = DtlsTransmitter.connect(localAddress(1_5684), conf, 6003).await()

        // then
        client.send("dupa")
        assertEquals("dupa", server.await().receiveString())
        assertEquals("01", server.await().getPeerCid()?.toHex())
        assertEquals("01", client.getOwnCid()?.toHex())

        println("val cliSession = \"" + client.saveSession().toHex() + "\".decodeHex()")
        println("val srvSession = \"" + server.await().saveSession().toHex() + "\".decodeHex()")
        client.close()
        conf.close()
        server.await().close()
    }

    @Test
    fun `should reload session`() {
        val cliSession = "030100003700000f0000006c0300000000629c5d94c0a400208ec2614e8a435bde158e4e387ecbacd089234536ae946fbfea2c4cd7d32f87c3777d703fa9ed1f8edf7ea245f4209aad7e20d1f21d74e89c142eb59b79007c93e0029948e8ed28219d479223015e97d9000000000000000000000000000000629c5d9458b9a4f7362b6ab93a92122d917f45d17a444ce5433708694cd8f3aa629c5d94a80b29e465e41a698d81d8ba929672ab16301b55e2876a03745a73b801011060317fc9746c7fa51aaf88e9c12be5ef0000000000000000000000000000000000000001000001000000000002000000".decodeHex()
        val srvSession = "030100003700000f0000006c0300000000629c5d94c0a400208ec2614e8a435bde158e4e387ecbacd089234536ae946fbfea2c4cd7d32f87c3777d703fa9ed1f8edf7ea245f4209aad7e20d1f21d74e89c142eb59b79007c93e0029948e8ed28219d479223015e97d9000000000000000000000000000001629c5d9458b9a4f7362b6ab93a92122d917f45d17a444ce5433708694cd8f3aa629c5d94a80b29e465e41a698d81d8ba929672ab16301b55e2876a03745a73b81060317fc9746c7fa51aaf88e9c12be5ef01010000000000000000000000010000000000000003000001000000000001000000".decodeHex()
        val clientConf = SslConfig.client("dupa".encodeToByteArray(), byteArrayOf(0x01, 0x02), listOf("TLS-PSK-WITH-AES-128-CCM"), { byteArrayOf(0x01) })
        srvTrans = ConnectedDatagramTransmitter.connect(localAddress(6004), 2_5684)

        // when
        val client = DtlsTransmitter.create(localAddress(2_5684), clientConf.loadSession(byteArrayOf(), cliSession, localAddress(2_5684)), 6004)
        val server = DtlsTransmitter.create(serverConf.loadSession(byteArrayOf(), srvSession, localAddress(6004)), srvTrans)
        runGC()

        // then
        client.send("hello!")
        assertEquals("hello!", server.receiveString())

        client.close()
        server.close()
    }

    @Test
    fun `should reuse session`() {
        val server = newServerDtlsTransmitter(6004)

        val clientConf = SslConfig.client(
            pskId = "dupa".encodeToByteArray(),
            pskSecret = byteArrayOf(0x01, 0x02),
            cidSupplier = { byteArrayOf(0x01) },
            cipherSuites = listOf("TLS-PSK-WITH-AES-128-CCM"),
        )

        // and
        val client = DtlsTransmitter.connect(localAddress(1_5684), clientConf, 6004).await()

        // when
        val storedSession: ByteArray = client.saveSession()
        assertTrue(storedSession.isNotEmpty())
        println(storedSession.size)
        client.close()
        val client2 = DtlsTransmitter.create(localAddress(1_5684), clientConf.loadSession(byteArrayOf(0x01), storedSession, localAddress(1_5684)), 6004)

        // then
        client2.send("dupa")
        assertEquals("dupa", server.await().receiveString())

        assertEquals("01", server.await().getPeerCid()?.toHex())
        clientConf.close()
        server.await().close()
    }

    @Test
    fun `should send close notify`() {
        // given
        val serverPromise = newServerDtlsTransmitter(6005)
        val conf = SslConfig.client("dupa".encodeToByteArray(), byteArrayOf(0x01, 0x02))

        val client = DtlsTransmitter.connect(localAddress(1_5684), conf, 6005).await()
        val server = serverPromise.await()

        // when
        client.closeNotify()

        // then
        val result = runCatching { server.receiveString() }
        assertEquals(
            "SSL - The peer notified us that the connection is going to be closed",
            result.exceptionOrNull()?.cause?.message
        )

        conf.close()
        server.close()
    }
}
