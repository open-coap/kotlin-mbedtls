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

import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.opencoap.ssl.PskAuth
import org.opencoap.ssl.SslConfig
import org.opencoap.ssl.util.StoredSessionPair
import org.opencoap.ssl.util.await
import org.opencoap.ssl.util.localAddress
import org.opencoap.ssl.util.runGC
import java.net.InetAddress
import java.net.InetSocketAddress
import java.nio.ByteBuffer
import java.time.Duration
import java.util.concurrent.CompletableFuture
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicReference
import kotlin.random.Random

class DtlsTransmitterTest {

    private val cidSupplier = { Random.nextBytes(16) }
    private val serverConf = SslConfig.server(PskAuth("device-007", byteArrayOf(0x01, 0x02)), cidSupplier = cidSupplier)
    private lateinit var srvTrans: Transport<ByteBuffer>

    @AfterEach
    fun after() {
        srvTrans.close()
        serverConf.close()
    }

    private fun newServerDtlsTransmitter(destLocalPort: Int): CompletableFuture<DtlsTransmitter> {
        srvTrans = DatagramChannelAdapter.connect(localAddress(destLocalPort), 1_5684)
        return DtlsTransmitter.connect(localAddress(destLocalPort), serverConf, srvTrans)
    }

    @Test
    fun `should successfully handshake and send data`() {
        val server = newServerDtlsTransmitter(6001)
        val conf = SslConfig.client(PskAuth("device-007", byteArrayOf(0x01, 0x02)))
        runGC() // make sure none of needed objects is garbage collected

        // when
        val client = DtlsTransmitter.connect(localAddress(1_5684), conf, 6001).await()
        assertEquals(localAddress(1_5684), client.remoteAddress)
        runGC() // make sure none of needed objects is garbage collected

        // then
        client.send("dupa")
        assertEquals("dupa", server.await().receiveString())
        // and read with timeout
        assertTrue(client.receive(Duration.ofMillis(1)).join().isEmpty())

        assertNotNull(client.cipherSuite)
        client.close()
        conf.close()
        server.await().close()
    }

    @Test
    fun `should fail to handshake - wrong psk`() {
        newServerDtlsTransmitter(6002)

        val conf = SslConfig.client(PskAuth("device-007", "bad".encodeToByteArray()))
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
            auth = PskAuth("device-007".encodeToByteArray(), byteArrayOf(0x01, 0x02)),
            cidSupplier = { byteArrayOf(0x01) },
            cipherSuites = listOf("TLS-PSK-WITH-AES-128-CCM"),
        )

        // when
        val client = DtlsTransmitter.connect(localAddress(1_5684), conf, 6003).await()

        // then
        client.send("dupa")
        assertEquals("dupa", server.await().receiveString())
        assertEquals("01", server.await().peerCid?.toHex())
        assertEquals("01", client.ownCid?.toHex())

        println("val cliSession = \"" + client.saveSession().toHex() + "\".decodeHex()")
        println("val srvSession = \"" + server.await().saveSession().toHex() + "\".decodeHex()")
        client.close()
        conf.close()
        server.await().close()
    }

    @Test
    fun `should reload session`() {
         val clientConf = SslConfig.client(PskAuth("dupa", byteArrayOf(0x01, 0x02)), cipherSuites = listOf("TLS-PSK-WITH-AES-128-CCM"), cidSupplier = { byteArrayOf(0x01) })
        srvTrans = DatagramChannelAdapter.connect(localAddress(6004), 2_5684)

        // when
        val client = DtlsTransmitter.create(localAddress(2_5684), clientConf.loadSession(byteArrayOf(), StoredSessionPair.cliSession, localAddress(2_5684)), 6004)
        val server = DtlsTransmitter.create(localAddress(6004), serverConf.loadSession(byteArrayOf(), StoredSessionPair.srvSession, localAddress(6004)), srvTrans)
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
            auth = PskAuth("device-007", byteArrayOf(0x01, 0x02)),
            cidSupplier = { byteArrayOf(0x01) },
            cipherSuites = listOf("TLS-PSK-WITH-AES-128-CCM"),
        )

        // and
        val storedSession = AtomicReference<ByteArray>()
        val client = DtlsTransmitter.connect(localAddress(1_5684), clientConf, 6004).await().storeOnClose { _, s -> storedSession.set(s) }

        // when
        client.close()
        assertTrue(storedSession.get().isNotEmpty())
        println(storedSession.get().size)
        val client2 = DtlsTransmitter.create(localAddress(1_5684), clientConf.loadSession(byteArrayOf(0x01), storedSession.get(), localAddress(1_5684)), 6004)

        // then
        client2.send("dupa")
        assertEquals("dupa", server.await().receiveString())

        assertEquals("01", server.await().peerCid?.toHex())
        clientConf.close()
        server.await().close()
    }

    @Test
    fun `should send close notify`() {
        // given
        val serverPromise = newServerDtlsTransmitter(6005)
        val conf = SslConfig.client(PskAuth("device-007", byteArrayOf(0x01, 0x02)))

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

    @Test
    fun `client usage example`() {
        val server = newServerDtlsTransmitter(6001)

        // create mbedtls SSL configuration with PSK credentials
        val conf: SslConfig = SslConfig.client(
            PskAuth(
                pskId = "device-007",
                pskSecret = byteArrayOf(0x01, 0x02)
            )
        )
        // create client and initiate handshake
        val client: DtlsTransmitter = DtlsTransmitter
            .connect(InetSocketAddress(InetAddress.getLocalHost(), 1_5684), conf, 6001)
            .get(10, TimeUnit.SECONDS)

        // send and receive packets
        val sendResult: CompletableFuture<Boolean> = client.send("hello")
        val receive: CompletableFuture<ByteBuffer> = client.receive(timeout = Duration.ofSeconds(2))

        // ---------------------
        assertEquals("hello", server.await().receiveString())
        server.await().send("hello2").await()
        assertTrue(sendResult.await())
        assertEquals("hello2", receive.await().decodeToString())
        // ---------------------

        // optionally, it is possible to save session before closing client, it could be later reloaded
        // note: after saving session, it is not possible to is client
        val storedSession: ByteArray = client.saveSession()
        client.close()

        // close SSL configuration:
        // - make sure to close it before GC to avoid native memory leak
        // - close it only after client is closed
        conf.close()

        // ---------------------
        server.await().close()
    }
}
