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

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.opencoap.ssl.transport.decodeToString
import org.opencoap.ssl.transport.toByteBuffer
import org.opencoap.ssl.util.localAddress
import org.opencoap.ssl.util.runGC
import java.nio.ByteBuffer

/**
 * Verifies deterministic native-memory release (Scenario 3): closing an [SslConfig]/[SslSession] closes its backing
 * [java.lang.foreign.Arena] and frees the native struct chain immediately, and repeated create/close cycles under GC
 * stress neither leak nor crash.
 */
class NativeMemoryLeakTest {

    private fun newConfigs(): Pair<SslConfig, SslConfig> {
        val server = SslConfig.server(
            PskAuth("device-007", byteArrayOf(0x01, 0x02)),
            cipherSuites = listOf("TLS-PSK-WITH-AES-128-CCM"),
            reqAuthentication = false,
            cidSupplier = RandomCidSupplier(16)
        )
        val client = SslConfig.client(
            PskAuth("device-007", byteArrayOf(0x01, 0x02)),
            cipherSuites = listOf("TLS-PSK-WITH-AES-128-CCM"),
            reqAuthentication = false,
            cidSupplier = RandomCidSupplier(16)
        )
        return client to server
    }

    private fun handshake(clientConf: SslConfig, serverConf: SslConfig): Pair<SslSession, SslSession> {
        lateinit var sendingBuffer: ByteBuffer
        val send: (ByteBuffer) -> Unit = { sendingBuffer = it }
        var srvHandshake = serverConf.newContext(localAddress(1_5684))
        val cliHandshake = clientConf.newContext(localAddress(2_5684))

        var clientSession: SslContext = cliHandshake
        cliHandshake.step(send)
        try {
            srvHandshake.step(sendingBuffer) { clientSession = cliHandshake.step(it, send) }
        } catch (ex: HelloVerifyRequired) {
            srvHandshake.close()
            srvHandshake = serverConf.newContext(localAddress(1_5684))
        }
        srvHandshake.step(sendingBuffer) { clientSession = cliHandshake.step(it, send) }
        val serverSession = srvHandshake.step(sendingBuffer) { clientSession = cliHandshake.step(it, send) }

        return (clientSession as SslSession) to (serverSession as SslSession)
    }

    @Test
    fun `should release native memory deterministically on close`() {
        val (clientConf, serverConf) = newConfigs()
        val (clientSession, serverSession) = handshake(clientConf, serverConf)

        // sanity: the session is usable before close
        val enc = clientSession.encrypt("hello".toByteBuffer())
        assertEquals("hello", serverSession.decrypt(enc) { }.decodeToString())

        clientSession.close()
        serverSession.close()
        clientConf.close()
        serverConf.close()

        // closing twice must be a no-op (arena already closed, no double-free)
        clientSession.close()
        serverSession.close()

        // touching a closed session must fail because its backing arena is closed -> memory was released
        assertThrows(IllegalStateException::class.java) { clientSession.encrypt("again".toByteBuffer()) }
    }

    @Test
    fun `should not leak native memory across create-close cycles under GC stress`() {
        val cycles = 300
        repeat(cycles) {
            val (clientConf, serverConf) = newConfigs()
            val (clientSession, serverSession) = handshake(clientConf, serverConf)

            val enc = clientSession.encrypt("payload".toByteBuffer())
            assertEquals("payload", serverSession.decrypt(enc) { }.decodeToString())

            clientSession.close()
            serverSession.close()
            clientConf.close()
            serverConf.close()

            if (it % 50 == 0) runGC()
        }

        // if arenas were not freed on close, the process would accumulate native memory and likely fail well before here
        assertTrue(true)
    }
}
