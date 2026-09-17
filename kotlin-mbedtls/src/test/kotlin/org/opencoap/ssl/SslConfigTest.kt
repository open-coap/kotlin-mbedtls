/*
 * Copyright (c) 2022-2025 kotlin-mbedtls contributors (https://github.com/open-coap/kotlin-mbedtls)
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

import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.opencoap.ssl.util.Certs
import java.security.PrivateKey

class SslConfigTest {

    // A PrivateKey whose DER encoding mbedtls cannot parse.
    private class InvalidPrivateKey : PrivateKey {
        override fun getAlgorithm(): String = "EC"
        override fun getFormat(): String = "PKCS#8"
        override fun getEncoded(): ByteArray = byteArrayOf(0x00, 0x01, 0x02, 0x03)
    }

    @Test
    fun `should fail fast when private key cannot be parsed`() {
        assertThrows(SslException::class.java) {
            SslConfig.client(CertificateAuth(Certs.serverChain, InvalidPrivateKey()))
        }
    }

    @Test
    fun `should create config with valid private key`() {
        val conf = SslConfig.client(CertificateAuth(Certs.serverChain, Certs.server.privateKey))
        conf.close()
    }

    // mbedtls keeps a native copy, so an un-wiped array only serves up every PSK in a heap dump
    @Test
    fun `should zero psk secret when config is closed`() {
        val secret = byteArrayOf(1, 2, 3, 4, 5, 6, 7, 8)
        val psk = PskAuth("device-007", secret)
        val conf = SslConfig.client(psk)

        assertTrue(secret.any { it != 0.toByte() }, "secret was already zeroed before close()")

        conf.close()

        assertTrue(secret.all { it == 0.toByte() }, "caller's array was not zeroed, bytes=${secret.toList()}")
        assertTrue(psk.pskSecret.all { it == 0.toByte() }, "PskAuth.pskSecret was not zeroed, bytes=${psk.pskSecret.toList()}")
    }

    @Test
    fun `should not touch certificate credentials when config is closed`() {
        val conf = SslConfig.client(CertificateAuth(Certs.serverChain, Certs.server.privateKey))

        conf.close()

        // Wiping a JCE PrivateKey is out of scope, so the key stays usable after close
        assertTrue(Certs.server.privateKey.encoded.any { it != 0.toByte() })
    }
}
