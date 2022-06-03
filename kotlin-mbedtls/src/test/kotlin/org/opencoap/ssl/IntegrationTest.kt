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

package org.opencoap.ssl

import org.opencoap.ssl.transport.DtlsTransmitter
import org.opencoap.ssl.transport.toHex
import org.opencoap.ssl.util.decodeHex
import org.opencoap.ssl.util.localAddress
import java.net.InetSocketAddress
import java.nio.channels.DatagramChannel
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

class IntegrationTest {

    private val serverConf =
        SslConfig.server("dupa".encodeToByteArray(), byteArrayOf(0x01, 0x02), cid = "db04684e33424e42801f0e38023d2438".decodeHex())
    private val serverChannel = DatagramChannel.open().bind(InetSocketAddress("0.0.0.0", 1_5684))

    @AfterTest
    fun after() {
        serverChannel.close()
        serverConf.close()
    }

    @Test
    fun `should successfully handshake and send data`() {
        val server = DtlsTransmitter.connect(localAddress(6001), serverConf, serverChannel)
        val conf = SslConfig.client("dupa".encodeToByteArray(), byteArrayOf(0x01, 0x02))
        runGC() // make sure none of needed objects is garbage collected

        // when
        val client = DtlsTransmitter.connect(localAddress(1_5684), conf, 6001).join()
        runGC() // make sure none of needed objects is garbage collected

        // then
        client.send("dupa")
        assertEquals("dupa", server.join().receiveString())
        assertNotNull(client.getCipherSuite())
        client.close()
        conf.close()
    }

    @Test
    fun `should fail to handshake - wrong psk`() {
        val server = DtlsTransmitter.connect(localAddress(6002), serverConf, serverChannel)

        val conf = SslConfig.client("dupa".encodeToByteArray(), "bad".encodeToByteArray())
        val client = DtlsTransmitter.connect(localAddress(1_5684), conf, 6002)

        assertTrue(
            runCatching { client.join() }
                .exceptionOrNull()?.cause?.message?.startsWith("SSL - A fatal alert message was received from our peer") == true
        )
        conf.close()
    }

    @Test
    fun `should use CID`() {
        val server = DtlsTransmitter.connect(localAddress(6003), serverConf, serverChannel)

        val conf = SslConfig.client(
            pskId = "dupa".encodeToByteArray(),
            pskSecret = byteArrayOf(0x01, 0x02),
            cid = byteArrayOf(0x01),
            cipherSuites = listOf("TLS-PSK-WITH-AES-128-CCM"),
        )

        // when
        val client = DtlsTransmitter.connect(localAddress(1_5684), conf, 6003).join()

        // then
        client.send("dupa")
        assertEquals("dupa", server.join().receiveString())

        assertEquals("01", server.join().getPeerCid()?.toHex())
        conf.close()
    }

    @Test
    fun `should reuse session`() {
        val server = DtlsTransmitter.connect(localAddress(6004), serverConf, serverChannel)

        val clientConf = SslConfig.client(
            pskId = "dupa".encodeToByteArray(),
            pskSecret = byteArrayOf(0x01, 0x02),
            cid = byteArrayOf(0x01),
            cipherSuites = listOf("TLS-PSK-WITH-AES-128-CCM"),
        )

        // and
        val client = DtlsTransmitter.connect(localAddress(1_5684), clientConf, 6004).join()

        // when
        val storedSession: ByteArray = client.saveSession()
        assertTrue(storedSession.isNotEmpty())
        println(storedSession.size)
        client.close()
        val client2 = DtlsTransmitter.create(localAddress(1_5684), clientConf.newContext(storedSession))

        // then
        client2.send("dupa")
        assertEquals("dupa", server.join().receiveString())

        assertEquals("01", server.join().getPeerCid()?.toHex())
        clientConf.close()
    }

    private fun runGC() {
        System.gc()
        Thread.sleep(100)
        System.gc()
    }
}
