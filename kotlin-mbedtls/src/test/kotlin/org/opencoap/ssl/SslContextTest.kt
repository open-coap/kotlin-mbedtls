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

package org.opencoap.ssl

import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.opencoap.ssl.transport.asByteBuffer
import org.opencoap.ssl.transport.copy
import org.opencoap.ssl.transport.decodeToString
import org.opencoap.ssl.transport.toByteBuffer
import org.opencoap.ssl.transport.toHex
import org.opencoap.ssl.util.Certs
import org.opencoap.ssl.util.StoredSessionPair
import org.opencoap.ssl.util.decodeHex
import org.opencoap.ssl.util.localAddress
import java.nio.ByteBuffer

class SslContextTest {
    val serverConf = SslConfig.server(CertificateAuth(Certs.serverChain, Certs.server.privateKey), reqAuthentication = false, cidSupplier = RandomCidSupplier(16), cipherSuites = listOf("TLS-ECDHE-ECDSA-WITH-AES-128-GCM-SHA256"))
    val clientConf = SslConfig.client(CertificateAuth.trusted(Certs.root.asX509()), cipherSuites = listOf("TLS-ECDHE-ECDSA-WITH-AES-128-GCM-SHA256"))

    @AfterEach
    fun tearDown() {
        serverConf.close()
        clientConf.close()
    }

    @Test
    fun `should peek CID from DTLS Packet`() {
        val dtlsPacket =
            "19fefd0001000000000001db04684e33424e42801f0e38023d243800280001000000000001a7eddd3aa34f5164499ca1fcaede85f9e77036ad66c2affb2ae9c97c5a78adb9"
                .decodeHex().asByteBuffer()

        val cid = SslContext.peekCID(16, dtlsPacket)

        assertEquals("db04684e33424e42801f0e38023d2438", cid?.toHex())
        assertEquals(0, dtlsPacket.position())
    }

    @Test
    fun `should peek CID from DTLS Packet with different sizes`() {
        assertEquals(
            "db",
            SslContext.peekCID(1, "19fefd0301000000000003db04684e3342".decodeHex().asByteBuffer())?.toHex()
        )
        assertEquals(
            "db04684e",
            SslContext.peekCID(4, "19fefdf001000000000001db04684e3342".decodeHex().asByteBuffer())?.toHex()
        )
    }

    @Test
    fun `should return null when not DTLS Packet`() {
        assertNull(SslContext.peekCID(4, "17fefd0001000000000001db04684e3342".decodeHex().asByteBuffer()))
        assertNull(SslContext.peekCID(4, "19f0fd0001000000000001db04684e3342".decodeHex().asByteBuffer()))
        assertNull(SslContext.peekCID(4, "19fef00001000000000001db04684e3342".decodeHex().asByteBuffer()))
    }

    @Test
    fun `should return null when too short DTLS Packet`() {
        assertNull(
            SslContext.peekCID(7, "19fefdf001000000000001db04684e3342".decodeHex().asByteBuffer())?.toHex()
        )
        assertNull(
            SslContext.peekCID(2, "19fefd".decodeHex().asByteBuffer())?.toHex()
        )
    }

    @Test
    fun `should handshake with certificate`() {
        lateinit var sendingBuffer: ByteBuffer
        val send: (ByteBuffer) -> Unit = { sendingBuffer = it }
        var srvHandshake = serverConf.newContext(localAddress(1_5684))
        val cliHandshake = clientConf.newContext(localAddress(2_5684))

        cliHandshake.step(send)
        try {
            srvHandshake.step(sendingBuffer) { cliHandshake.step(it, send) }
        } catch (ex: HelloVerifyRequired) {
            srvHandshake.close()
            srvHandshake = serverConf.newContext(localAddress(1_5684))
        }
        srvHandshake.step(sendingBuffer) { cliHandshake.step(it, send) }

        // last step
        val serverSslSession = srvHandshake.step(sendingBuffer) {
            assertTrue(cliHandshake.step(it, send) is SslSession)
        }

        assertTrue(serverSslSession is SslSession)
        serverSslSession.close()
    }

    @Test
    fun `should load sessions and exchange data`() {
        val clientSession = clientConf.loadSession(byteArrayOf(), StoredSessionPair.cliSession, localAddress(2_5684))
        val serverSession = serverConf.loadSession(byteArrayOf(), StoredSessionPair.srvSession, localAddress(1_5684))

        val encryptedDtls = clientSession.encrypt("perse".toByteBuffer())
        assertEquals("perse", serverSession.decrypt(encryptedDtls, noSend).decodeToString())

        // buffer with shifted position
        val buf = "--perse--".toByteBuffer()
        buf.position(2)
        buf.limit(7)
        val encryptedDtls2 = clientSession.encrypt(buf)
        assertEquals("perse", serverSession.decrypt(encryptedDtls2, noSend).decodeToString())
    }

    @Test
    fun `should verify session is valid authentic and decrypt`() {
        val clientSession = clientConf.loadSession(byteArrayOf(), StoredSessionPair.cliSession, localAddress(2_5684))
        val serverSession = serverConf.loadSession(byteArrayOf(), StoredSessionPair.srvSession, localAddress(1_5684))

        val encryptedDtls = clientSession.encrypt("auto".toByteBuffer()).copy()

        assertTrue(serverSession.verifyRecord(encryptedDtls).isValid)
        assertEquals("auto", serverSession.decrypt(encryptedDtls, noSend).decodeToString())
    }

    @Test
    fun `should exchange data with direct byte buffer`() {
        val clientSession = clientConf.loadSession(byteArrayOf(), StoredSessionPair.cliSession, localAddress(2_5684))
        val serverSession = serverConf.loadSession(byteArrayOf(), StoredSessionPair.srvSession, localAddress(1_5684))

        // direct memory with shifted position
        val buf = ByteBuffer.allocateDirect(10)
        buf.put("--dupa".encodeToByteArray())
        buf.flip()
        buf.position(2)
        val encryptedDtls3 = clientSession.encrypt(buf)

        buf.clear()
        buf.put("==".encodeToByteArray())
        serverSession.decrypt(encryptedDtls3, buf, noSend)
        assertEquals("dupa", buf.decodeToString())

        clientSession.close()
        serverSession.close()
    }

    private val noSend: (ByteBuffer) -> Unit = { throw IllegalStateException() }
}
