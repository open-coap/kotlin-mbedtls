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

import org.opencoap.ssl.transport.toHex
import org.slf4j.LoggerFactory
import java.io.Closeable
import java.net.InetSocketAddress
import java.security.PrivateKey
import java.security.cert.X509Certificate
import java.time.Duration
import java.time.Duration.ofSeconds

class SslConfig internal constructor(
    private val engine: Mbedtls,
    private val conf: NativeConf,
    val cidSupplier: CidSupplier?,
    private val mtu: Int,
) : Closeable {
    private val logger = LoggerFactory.getLogger(javaClass)

    fun newContext(peerAddress: InetSocketAddress): SslHandshakeContext {
        val cid = cidSupplier?.next()
        val bio = Bio()
        val ctx = engine.newContext(conf, cid, mtu, peerAddress, bio)
        return SslHandshakeContext(engine, this, ctx, bio, cid, peerAddress)
    }

    fun loadSession(cid: ByteArray, session: ByteArray, peerAddress: InetSocketAddress): SslSession {
        val bio = Bio()
        val ctx = engine.loadContext(conf, session, bio)
        return SslSession(engine, this, ctx, bio, cid, true).also {
            logger.info("[{}] [{}] DTLS session reloaded {}", peerAddress, cid.toHex(), it)
        }
    }

    override fun close() {
        engine.freeConfig(conf)
    }

    companion object {

        @JvmStatic
        @JvmOverloads
        fun client(engine: Mbedtls, auth: AuthConfig, cipherSuites: List<String> = emptyList(), reqAuthentication: Boolean = true, cidSupplier: CidSupplier? = EmptyCidSupplier, retransmitMin: Duration = ofSeconds(1), retransmitMax: Duration = ofSeconds(60)): SslConfig = create(engine, false, auth, cipherSuites, cidSupplier, reqAuthentication, 0, retransmitMin, retransmitMax)

        @JvmStatic
        @JvmOverloads
        fun server(engine: Mbedtls, auth: AuthConfig, cipherSuites: List<String> = emptyList(), reqAuthentication: Boolean = true, cidSupplier: CidSupplier? = EmptyCidSupplier, mtu: Int = 0, retransmitMin: Duration = ofSeconds(1), retransmitMax: Duration = ofSeconds(60)): SslConfig = create(engine, true, auth, cipherSuites, cidSupplier, reqAuthentication, mtu, retransmitMin, retransmitMax)

        @Suppress("LongParameterList")
        private fun create(
            engine: Mbedtls,
            isServer: Boolean,
            authConfig: AuthConfig,
            cipherSuites: List<String>,
            cidSupplier: CidSupplier?,
            requiredAuthMode: Boolean,
            mtu: Int,
            retransmitMin: Duration,
            retransmitMax: Duration
        ): SslConfig {
            val cidLength = if (cidSupplier != null && cidSupplier != EmptyCidSupplier) cidSupplier.next().size else 0
            val spec = ConfigSpec(
                isServer = isServer,
                auth = authConfig,
                cipherSuites = cipherSuites,
                requiredAuthMode = requiredAuthMode,
                cidLength = cidLength,
                retransmitMinMillis = retransmitMin.toMillis().toInt(),
                retransmitMaxMillis = retransmitMax.toMillis().toInt(),
            )
            return SslConfig(engine, engine.buildConfig(spec), cidSupplier, mtu)
        }
    }
}

/** Authentication configuration as pure data; engines interpret it in [Mbedtls.buildConfig]. */
sealed interface AuthConfig

data class PskAuth(
    val pskId: ByteArray,
    val pskSecret: ByteArray
) : AuthConfig {

    constructor(pskId: String, pskSecret: ByteArray) : this(pskId.encodeToByteArray(), pskSecret)
}

data class CertificateAuth(
    val ownCertChain: List<X509Certificate>,
    val privateKey: PrivateKey?,
    val trustedCerts: List<X509Certificate>
) : AuthConfig {

    constructor(ownCertChain: List<X509Certificate>, privateKey: PrivateKey, trustedCert: X509Certificate) :
        this(ownCertChain, privateKey, listOf(trustedCert))

    constructor(ownCertChain: List<X509Certificate>, privateKey: PrivateKey) :
        this(ownCertChain, privateKey, listOf())

    companion object {
        @JvmStatic
        fun trusted(trustedCerts: List<X509Certificate>) = CertificateAuth(listOf(), null, trustedCerts.toList())

        @JvmStatic
        fun trusted(vararg trustedCerts: X509Certificate) = trusted(trustedCerts.toList())
    }
}
