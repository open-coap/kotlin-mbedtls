/*
 * Copyright (c) 2022-2026 kotlin-mbedtls contributors (https://github.com/open-coap/kotlin-mbedtls)
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
import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertSame
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Test
import org.opencoap.ssl.transport.decodeToString
import org.opencoap.ssl.transport.toByteBuffer
import org.opencoap.ssl.util.Certs
import org.opencoap.ssl.util.StoredSessionPair
import org.opencoap.ssl.util.decodeHex
import org.opencoap.ssl.util.localAddress
import java.nio.ByteBuffer

class StoredSessionVersionTest {
    private val serverConf = SslConfig.server(CertificateAuth(Certs.serverChain, Certs.server.privateKey), reqAuthentication = false, cidSupplier = RandomCidSupplier(16), cipherSuites = listOf("TLS-ECDHE-ECDSA-WITH-AES-128-GCM-SHA256"))
    private val clientConf = SslConfig.client(CertificateAuth.trusted(Certs.root.asX509()), cipherSuites = listOf("TLS-ECDHE-ECDSA-WITH-AES-128-GCM-SHA256"))
    private val noSend: (ByteBuffer) -> Unit = { throw IllegalStateException() }

    private val v410 = StoredSessions.load("mbedtls-4.1.0.txt")

    @AfterEach
    fun tearDown() {
        serverConf.close()
        clientConf.close()
    }

    @Test
    fun `should read mbedtls version of stored session`() {
        assertEquals(MbedtlsVersion(4, 1, 0), StoredSessionVersion.of(v410.srvSession))
        assertEquals(MbedtlsVersion(4, 1, 0), StoredSessionVersion.of(v410.cliSession))
    }

    @Test
    fun `should read running mbedtls version of freshly saved session`() {
        assertEquals(StoredSessionVersion.current, StoredSessionVersion.of(StoredSessionPair.srvSession))
        assertEquals("4.2.0", StoredSessionVersion.current.toString())
    }

    @Test
    fun `should not read version of too short session`() {
        assertNull(StoredSessionVersion.of(byteArrayOf(4, 1)))
    }

    @Test
    fun `should upgrade session stored by previous mbedtls version`() {
        val upgraded = StoredSessionVersion.upgrade(v410.srvSession)

        assertEquals(StoredSessionVersion.current, StoredSessionVersion.of(upgraded))
        assertArrayEquals(v410.srvSession.copyOfRange(3, v410.srvSession.size), upgraded.copyOfRange(3, upgraded.size))
        // input is not modified
        assertEquals(MbedtlsVersion(4, 1, 0), StoredSessionVersion.of(v410.srvSession))
    }

    @Test
    fun `should not change session stored by running mbedtls version`() {
        assertSame(StoredSessionPair.srvSession, StoredSessionVersion.upgrade(StoredSessionPair.srvSession))
    }

    @Test
    fun `should not change session stored by unsupported mbedtls version`() {
        val v400 = v410.srvSession.withVersion(4, 0, 0)

        assertSame(v400, StoredSessionVersion.upgrade(v400))
        assertThrows(SslException::class.java) { serverConf.loadSession(byteArrayOf(), v400, localAddress(1_5684)) }
    }

    @Test
    fun `should not change too short session`() {
        val session = byteArrayOf(4, 1)

        assertSame(session, StoredSessionVersion.upgrade(session))
    }

    // When this fails after an mbedtls upgrade: compare serialisation (mbedtls_ssl_context_save/load) of the
    // previous and the new mbedtls version, update StoredSessionVersion and replace the stored-sessions fixture
    // with one saved by the previous version.
    @Test
    fun `should load sessions stored by previous mbedtls version and exchange data`() {
        val clientSession = clientConf.loadSession(byteArrayOf(), v410.cliSession, localAddress(2_5684))
        val serverSession = serverConf.loadSession(v410.cid, v410.srvSession, localAddress(1_5684))

        assertEquals("perse", serverSession.decrypt(clientSession.encrypt("perse".toByteBuffer()), noSend).decodeToString())
        assertEquals("dupa", clientSession.decrypt(serverSession.encrypt("dupa".toByteBuffer()), noSend).decodeToString())

        clientSession.close()
        serverSession.close()
    }

    private fun ByteArray.withVersion(major: Int, minor: Int, patch: Int): ByteArray = copyOf().also {
        it[0] = major.toByte()
        it[1] = minor.toByte()
        it[2] = patch.toByte()
    }

    private class StoredSessions(val cid: ByteArray, val cliSession: ByteArray, val srvSession: ByteArray) {
        companion object {
            fun load(name: String): StoredSessions {
                val values = StoredSessionVersionTest::class.java.getResource("/stored-sessions/$name")!!.readText()
                    .lines()
                    .filter { it.isNotBlank() && !it.startsWith("#") }
                    .associate { it.substringBefore('=') to it.substringAfter('=').decodeHex() }
                return StoredSessions(values.getValue("cid"), values.getValue("cli"), values.getValue("srv"))
            }
        }
    }
}
