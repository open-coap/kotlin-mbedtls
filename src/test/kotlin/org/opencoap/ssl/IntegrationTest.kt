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

import org.opencoap.ssl.util.localAddress
import java.net.InetSocketAddress
import java.nio.channels.DatagramChannel
import kotlin.test.*


class IntegrationTest {

    private val serverConf = SslConfig.server("dupa".encodeToByteArray(), byteArrayOf(0x01, 0x02))
    private val serverChannel = DatagramChannel.open().bind(localAddress(1_5684))

    @AfterTest
    fun after() {
        serverChannel.close()
    }

    @Test
    fun `should successfully handshake and send data`() {
        val client = SslConfig.client("dupa".encodeToByteArray(), byteArrayOf(0x01, 0x02))
            .newContext(DatagramChannelTransport.create(6001, localAddress(1_5684)))

        val serverSession = serverConf
            .newContext(DatagramChannelTransport(serverChannel, localAddress(6001)))
            .handshake()


        val clientSession = client.handshake().join()

        runGC() // make sure none of needed objects is garbage collected
        clientSession.send("dupa".encodeToByteArray())
        val data = serverSession.get().read()
        assertEquals("dupa", data.join().decodeToString())
        assertNotNull(clientSession.getCipherSuite())
    }

    @Test
    fun `should fail to handshake - wrong psk`() {
        val client = SslConfig.client("dupa".encodeToByteArray(), "bad".encodeToByteArray())
            .newContext(DatagramChannelTransport.create(6002, localAddress(1_5684)))

        serverConf
            .newContext(DatagramChannelTransport(serverChannel, localAddress(6002)))
            .handshake()

        assertTrue(
            runCatching { client.handshake().join() }
                .exceptionOrNull()?.cause?.message?.startsWith("SSL - A fatal alert message was received from our peer") == true
        )

    }

    @Test
    fun testServer() {
        val conf: SslConfig = SslConfig.server("dupa".encodeToByteArray(), byteArrayOf(1))

        val server = DtlsServer(6100, conf) { _: InetSocketAddress, _: ByteArray ->
            "dupa".encodeToByteArray()
        }.start()


        Thread.sleep(100)

        val client = SslConfig.client("dupa".encodeToByteArray(), byteArrayOf(1))
            .newContext(DatagramChannelTransport.create(6101, localAddress(6100)))
        val clientSession = client.handshake().join()

        clientSession.send("perse".encodeToByteArray())
        assertEquals("dupa", clientSession.read().join().decodeToString())

        server.stop()
    }

    private fun runGC() {
        System.gc()
        Thread.sleep(100)
        System.gc()
    }

}
