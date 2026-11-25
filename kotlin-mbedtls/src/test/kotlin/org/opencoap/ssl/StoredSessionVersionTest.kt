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
        assertEquals(0x04010000, StoredSessionVersion.of(v410.srvSession))
        assertEquals(0x04010000, StoredSessionVersion.of(v410.cliSession))
    }

    @Test
    fun `should read running mbedtls version of freshly saved session`() {
        assertEquals(StoredSessionVersion.current, StoredSessionVersion.of(StoredSessionPair.srvSession))
        assertEquals(0x04020000, StoredSessionVersion.current)
    }

    @Test
    fun `should not read version of too short session`() {
        assertNull(StoredSessionVersion.of(byteArrayOf(4, 1)))
    }

    @Test
    fun `should upgrade session stored by previous mbedtls version`() {
        val original = v410.srvSession.copyOf()

        val upgraded = StoredSessionVersion.upgrade(v410.srvSession)

        assertEquals(StoredSessionVersion.current, StoredSessionVersion.of(upgraded))
        assertArrayEquals(original.copyOfRange(3, original.size), upgraded.copyOfRange(3, upgraded.size))
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

    @Test
    fun `should upgrade session through multiple mbedtls versions`() {
        val v400 = v410.srvSession.withVersion(4, 0, 0)
        val original = v400.copyOf()
        val chain = listOf(Upgrade(from = 0x04000000, to = 0x04010000), Upgrade(from = 0x04010000, to = 0x04020000))

        val upgraded = StoredSessionVersion.upgrade(v400, chain, target = 0x04020000)

        assertEquals(0x04020000, StoredSessionVersion.of(upgraded))
        assertArrayEquals(original.copyOfRange(3, original.size), upgraded.copyOfRange(3, upgraded.size))
    }

    @Test
    fun `should not change session when upgrades do not reach running mbedtls version`() {
        val v400 = v410.srvSession.withVersion(4, 0, 0)
        val original = v400.copyOf()
        val chain = listOf(Upgrade(from = 0x04000000, to = 0x04010000))

        val upgraded = StoredSessionVersion.upgrade(v400, chain, target = 0x04020000)

        assertSame(v400, upgraded)
        assertArrayEquals(original, upgraded)
    }

    // When this fails after an mbedtls upgrade: compare serialisation (mbedtls_ssl_context_save/load) of the
    // previous and the new mbedtls version, add an Upgrade to StoredSessionVersion.upgrades and add a
    // stored-sessions fixture saved by the previous version.
    @Test
    fun `should upgrade one version after another up to running mbedtls version`() {
        val upgrades = StoredSessionVersion.upgrades

        assertEquals(StoredSessionVersion.current, upgrades.last().to)
        upgrades.zipWithNext().forEach { (prev, next) -> assertEquals(prev.to, next.from) }
    }

    @TestFactory
    fun `should load sessions stored by upgradable mbedtls version and exchange data`(): List<DynamicTest> = StoredSessionVersion.upgrades.map { upgrade ->
        dynamicTest(upgrade.from.format()) {
            val stored = StoredSessions.load("mbedtls-${upgrade.from.format()}.txt")
            val clientSession = clientConf.loadSession(byteArrayOf(), stored.cliSession, localAddress(2_5684))
            val serverSession = serverConf.loadSession(stored.cid, stored.srvSession, localAddress(1_5684))

            assertEquals("perse", serverSession.decrypt(clientSession.encrypt("perse".toByteBuffer()), noSend).decodeToString())
            assertEquals("dupa", clientSession.decrypt(serverSession.encrypt("dupa".toByteBuffer()), noSend).decodeToString())

            clientSession.close()
            serverSession.close()
        }
    }

    private fun MbedtlsVersion.format(): String = "${this ushr 24 and 0xFF}.${this ushr 16 and 0xFF}.${this ushr 8 and 0xFF}"

    private fun ByteArray.withVersion(major: Int, minor: Int, patch: Int): ByteArray = copyOf().also {
        it[0] = major.toByte()
        it[1] = minor.toByte()
        it[2] = patch.toByte()
    }

    private class StoredSessions(val cid: ByteArray, val cliSession: ByteArray, val srvSession: ByteArray) {
        companion object {
            fun load(name: String): StoredSessions {
                val resource = checkNotNull(StoredSessionVersionTest::class.java.getResource("/stored-sessions/$name")) { "Missing fixture: stored-sessions/$name" }
                val values = resource.readText()
                    .lines()
                    .filter { it.isNotBlank() && !it.startsWith("#") }
                    .associate { it.substringBefore('=') to it.substringAfter('=').decodeHex() }
                return StoredSessions(values.getValue("cid"), values.getValue("cli"), values.getValue("srv"))
            }
        }
    }
}
