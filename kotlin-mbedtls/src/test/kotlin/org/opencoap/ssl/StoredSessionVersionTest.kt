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
import org.junit.jupiter.api.DynamicTest
import org.junit.jupiter.api.DynamicTest.dynamicTest
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestFactory
import org.opencoap.ssl.transport.decodeToString
import org.opencoap.ssl.transport.toByteBuffer
import org.opencoap.ssl.util.Certs
import org.opencoap.ssl.util.StoredSessionPair
import org.opencoap.ssl.util.decodeHex
import org.opencoap.ssl.util.localAddress
import java.io.File
import java.nio.ByteBuffer

class StoredSessionVersionTest {
    private val serverConf = SslConfig.server(CertificateAuth(Certs.serverChain, Certs.server.privateKey), reqAuthentication = false, cidSupplier = RandomCidSupplier(16), cipherSuites = listOf("TLS-ECDHE-ECDSA-WITH-AES-128-GCM-SHA256"))
    private val clientConf = SslConfig.client(CertificateAuth.trusted(Certs.root.asX509()), cipherSuites = listOf("TLS-ECDHE-ECDSA-WITH-AES-128-GCM-SHA256"))
    private val noSend: (ByteBuffer) -> Unit = { throw IllegalStateException() }

    private val v410 = StoredSessions.load(fixture("mbedtls-4.1.0.txt"))

    @AfterEach
    fun tearDown() {
        serverConf.close()
        clientConf.close()
    }

    @Test
    fun `should read mbedtls version of stored session`() {
        assertEquals(0x04010000, StoredSessionVersion.of(v410.srvSession))
        assertEquals(0x04010000, StoredSessionVersion.of(v410.cliSession))
    }

    @Test
    fun `should read running mbedtls version of freshly saved session`() {
        assertEquals(0x04020000, StoredSessionVersion.of(StoredSessionPair.srvSession))
        assertEquals(0x04020000, StoredSessionVersion.current)
    }

    @Test
    fun `should upgrade session stored by previous mbedtls version`() {
        // given
        val original = v410.srvSession.copyOf()

        // when
        val upgraded = StoredSessionVersion.upgrade(v410.srvSession)

        // then
        assertArrayEquals(byteArrayOf(4, 2, 0), upgraded.copyOfRange(0, 3))
        assertArrayEquals(original.copyOfRange(3, original.size), upgraded.copyOfRange(3, upgraded.size))
    }

    @Test
    fun `should not change session stored by running mbedtls version`() {
        assertSame(StoredSessionPair.srvSession, StoredSessionVersion.upgrade(StoredSessionPair.srvSession))
    }

    @Test
    fun `should not change session stored by unsupported mbedtls version`() {
        // given
        val v400 = v410.srvSession.withVersion(4, 0, 0)
        val original = v400.copyOf()

        // when
        val upgraded = StoredSessionVersion.upgrade(v400)

        // then
        assertArrayEquals(original, upgraded)
        // and, mbedtls still refuses it
        assertThrows(SslException::class.java) { serverConf.loadSession(byteArrayOf(), upgraded, localAddress(1_5684)) }
    }

    @Test
    fun `should not change too short session`() {
        // given
        val session = byteArrayOf(4, 1)

        // when
        val upgraded = StoredSessionVersion.upgrade(session)

        // then
        assertArrayEquals(byteArrayOf(4, 1), upgraded)
        // and, it has no version
        assertNull(StoredSessionVersion.of(session))
    }

    @Test
    fun `should upgrade session through multiple mbedtls versions`() {
        // given
        val v400 = v410.srvSession.withVersion(4, 0, 0)
        val original = v400.copyOf()
        val chain = listOf(Upgrade(from = 0x04000000, to = 0x04010000), Upgrade(from = 0x04010000, to = 0x04020000))

        // when
        val upgraded = StoredSessionVersion.upgrade(v400, chain, target = 0x04020000)

        // then
        assertArrayEquals(byteArrayOf(4, 2, 0), upgraded.copyOfRange(0, 3))
        assertArrayEquals(original.copyOfRange(3, original.size), upgraded.copyOfRange(3, upgraded.size))
    }

    @Test
    fun `should not change session when upgrades do not reach running mbedtls version`() {
        // given
        val v400 = v410.srvSession.withVersion(4, 0, 0)
        val original = v400.copyOf()
        val chain = listOf(Upgrade(from = 0x04000000, to = 0x04010000))

        // when
        val upgraded = StoredSessionVersion.upgrade(v400, chain, target = 0x04020000)

        // then
        assertArrayEquals(original, upgraded)
    }

    // When this fails after an mbedtls upgrade: compare serialisation (mbedtls_ssl_context_save/load) of the
    // previous and the new mbedtls version, add an Upgrade to StoredSessionVersion.upgrades and add a
    // stored-sessions fixture saved by the previous version.
    @TestFactory
    fun `should load sessions stored by older mbedtls versions and exchange data`(): List<DynamicTest> = fixture("").listFiles()!!.sorted().map { file ->
        dynamicTest(file.name) {
            // given
            val stored = StoredSessions.load(file)

            // when
            val clientSession = clientConf.loadSession(byteArrayOf(), stored.cliSession, localAddress(2_5684))
            val serverSession = serverConf.loadSession(byteArrayOf(), stored.srvSession, localAddress(1_5684))

            // then
            assertEquals("perse", serverSession.decrypt(clientSession.encrypt("perse".toByteBuffer()), noSend).decodeToString())
            assertEquals("dupa", clientSession.decrypt(serverSession.encrypt("dupa".toByteBuffer()), noSend).decodeToString())

            clientSession.close()
            serverSession.close()
        }
    }

    private fun fixture(name: String): File = File(checkNotNull(javaClass.getResource("/stored-sessions/$name")).toURI())

    private fun ByteArray.withVersion(major: Int, minor: Int, patch: Int): ByteArray = copyOf().also {
        it[0] = major.toByte()
        it[1] = minor.toByte()
        it[2] = patch.toByte()
    }

    private class StoredSessions(val cliSession: ByteArray, val srvSession: ByteArray) {
        companion object {
            fun load(file: File): StoredSessions {
                val values = file.readLines()
                    .filter { it.isNotBlank() && !it.startsWith("#") }
                    .associate { it.substringBefore('=') to it.substringAfter('=').decodeHex() }
                return StoredSessions(values.getValue("cli"), values.getValue("srv"))
            }
        }
    }
}
