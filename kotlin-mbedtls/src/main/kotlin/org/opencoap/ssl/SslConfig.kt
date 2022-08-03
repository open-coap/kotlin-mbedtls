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

import com.sun.jna.Callback
import com.sun.jna.Memory
import com.sun.jna.Pointer
import org.opencoap.ssl.MbedtlsApi.mbedtls_ctr_drbg_free
import org.opencoap.ssl.MbedtlsApi.mbedtls_ctr_drbg_random
import org.opencoap.ssl.MbedtlsApi.mbedtls_ctr_drbg_seed
import org.opencoap.ssl.MbedtlsApi.mbedtls_entropy_free
import org.opencoap.ssl.MbedtlsApi.mbedtls_pk_free
import org.opencoap.ssl.MbedtlsApi.mbedtls_pk_parse_key
import org.opencoap.ssl.MbedtlsApi.mbedtls_ssl_conf_authmode
import org.opencoap.ssl.MbedtlsApi.mbedtls_ssl_conf_ca_chain
import org.opencoap.ssl.MbedtlsApi.mbedtls_ssl_conf_cid
import org.opencoap.ssl.MbedtlsApi.mbedtls_ssl_conf_ciphersuites
import org.opencoap.ssl.MbedtlsApi.mbedtls_ssl_conf_dbg
import org.opencoap.ssl.MbedtlsApi.mbedtls_ssl_conf_dtls_cookies
import org.opencoap.ssl.MbedtlsApi.mbedtls_ssl_conf_handshake_timeout
import org.opencoap.ssl.MbedtlsApi.mbedtls_ssl_conf_min_version
import org.opencoap.ssl.MbedtlsApi.mbedtls_ssl_conf_own_cert
import org.opencoap.ssl.MbedtlsApi.mbedtls_ssl_conf_psk
import org.opencoap.ssl.MbedtlsApi.mbedtls_ssl_conf_rng
import org.opencoap.ssl.MbedtlsApi.mbedtls_ssl_config_defaults
import org.opencoap.ssl.MbedtlsApi.mbedtls_ssl_config_free
import org.opencoap.ssl.MbedtlsApi.mbedtls_ssl_context_load
import org.opencoap.ssl.MbedtlsApi.mbedtls_ssl_cookie_check
import org.opencoap.ssl.MbedtlsApi.mbedtls_ssl_cookie_free
import org.opencoap.ssl.MbedtlsApi.mbedtls_ssl_cookie_setup
import org.opencoap.ssl.MbedtlsApi.mbedtls_ssl_cookie_write
import org.opencoap.ssl.MbedtlsApi.mbedtls_ssl_get_ciphersuite_id
import org.opencoap.ssl.MbedtlsApi.mbedtls_ssl_set_bio
import org.opencoap.ssl.MbedtlsApi.mbedtls_ssl_set_cid
import org.opencoap.ssl.MbedtlsApi.mbedtls_ssl_set_client_transport_id
import org.opencoap.ssl.MbedtlsApi.mbedtls_ssl_set_mtu
import org.opencoap.ssl.MbedtlsApi.mbedtls_ssl_set_timer_cb
import org.opencoap.ssl.MbedtlsApi.mbedtls_ssl_setup
import org.opencoap.ssl.MbedtlsApi.mbedtls_x509_crt_free
import org.opencoap.ssl.MbedtlsApi.mbedtls_x509_crt_parse_der
import org.opencoap.ssl.MbedtlsApi.verify
import org.slf4j.LoggerFactory
import java.io.Closeable
import java.net.InetSocketAddress
import java.security.Key
import java.security.PrivateKey
import java.security.cert.X509Certificate
import java.time.Duration
import java.time.Duration.ofSeconds

class SslConfig(
    private val conf: Memory,
    val cidSupplier: CidSupplier,
    private val mtu: Int,
    private val close: Closeable
) : Closeable by close {
    private val logger = LoggerFactory.getLogger(javaClass)

    fun newContext(peerAddress: InetSocketAddress): SslHandshakeContext {
        val sslContext = Memory(MbedtlsSizeOf.mbedtls_ssl_context).apply(MbedtlsApi::mbedtls_ssl_init)

        mbedtls_ssl_setup(sslContext, conf).verify()
        mbedtls_ssl_set_timer_cb(sslContext, Pointer.NULL, NoOpsSetDelayCallback, NoOpsGetDelayCallback)

        val cid = cidSupplier.next()
        mbedtls_ssl_set_cid(sslContext, 1, cid, cid.size).verify()
        mbedtls_ssl_set_mtu(sslContext, mtu)

        val clientId = peerAddress.toString()
        mbedtls_ssl_set_client_transport_id(sslContext, clientId, clientId.length)

        mbedtls_ssl_set_bio(sslContext, Pointer.NULL, SendCallback, null, ReceiveCallback)

        return SslHandshakeContext(this, sslContext, cid, peerAddress)
    }

    fun loadSession(cid: ByteArray, session: ByteArray, peerAddress: InetSocketAddress): SslSession {
        val sslContext = Memory(MbedtlsSizeOf.mbedtls_ssl_context).apply(MbedtlsApi::mbedtls_ssl_init)

        mbedtls_ssl_setup(sslContext, conf).verify()
        mbedtls_ssl_context_load(sslContext, session, session.size).verify()
        mbedtls_ssl_set_bio(sslContext, Pointer.NULL, SendCallback, null, ReceiveCallback)

        return SslSession(this, sslContext, cid).also {
            logger.info("[{}] Reconnected {}", peerAddress, it)
        }
    }

    companion object {

        @JvmStatic
        @JvmOverloads
        fun client(pskId: ByteArray, pskSecret: ByteArray, cipherSuites: List<String> = emptyList(), cidSupplier: CidSupplier = EmptyCidSupplier, retransmitMin: Duration = ofSeconds(1), retransmitMax: Duration = ofSeconds(60)): SslConfig {
            return create(false, pskId, pskSecret, cipherSuites, cidSupplier, listOf(), null, listOf(), true, 0, retransmitMin, retransmitMax)
        }

        @JvmStatic
        @JvmOverloads
        fun server(pskId: ByteArray, pskSecret: ByteArray, cipherSuites: List<String> = emptyList(), cidSupplier: CidSupplier = EmptyCidSupplier, retransmitMin: Duration = ofSeconds(1), retransmitMax: Duration = ofSeconds(60)): SslConfig {
            return create(true, pskId, pskSecret, cipherSuites, cidSupplier, listOf(), null, listOf(), true, 0, retransmitMin, retransmitMax)
        }

        @JvmStatic
        @JvmOverloads
        fun client(ownCertChain: List<X509Certificate> = listOf(), privateKey: PrivateKey? = null, trustedCerts: List<X509Certificate>, cipherSuites: List<String> = listOf(), cidSupplier: CidSupplier = EmptyCidSupplier, mtu: Int = 0, retransmitMin: Duration = ofSeconds(1), retransmitMax: Duration = ofSeconds(60)): SslConfig {
            return create(false, null, null, cipherSuites, cidSupplier, ownCertChain, privateKey, trustedCerts, true, mtu, retransmitMin, retransmitMax)
        }

        @JvmStatic
        @JvmOverloads
        fun server(ownCertChain: List<X509Certificate>, privateKey: PrivateKey, trustedCerts: List<X509Certificate> = listOf(), reqAuthentication: Boolean = true, cipherSuites: List<String> = emptyList(), cidSupplier: CidSupplier = EmptyCidSupplier, mtu: Int = 0, retransmitMin: Duration = ofSeconds(1), retransmitMax: Duration = ofSeconds(60)): SslConfig {
            return create(true, null, null, cipherSuites, cidSupplier, ownCertChain, privateKey, trustedCerts, reqAuthentication, mtu, retransmitMin, retransmitMax)
        }

        private fun create(
            isServer: Boolean,
            pskId: ByteArray?,
            pskSecret: ByteArray?,
            cipherSuites: List<String>,
            cidSupplier: CidSupplier,
            ownCertChain: List<X509Certificate>,
            privateKey: Key?,
            trustedCerts: List<X509Certificate>,
            requiredAuthMode: Boolean = true,
            mtu: Int,
            retransmitMin: Duration,
            retransmitMax: Duration,
        ): SslConfig {

            val sslConfig = Memory(MbedtlsSizeOf.mbedtls_ssl_config).also(MbedtlsApi::mbedtls_ssl_config_init)
            val entropy = Memory(MbedtlsSizeOf.mbedtls_entropy_context).also(MbedtlsApi::mbedtls_entropy_init)
            val ctrDrbg = Memory(MbedtlsSizeOf.mbedtls_ctr_drbg_context).also(MbedtlsApi::mbedtls_ctr_drbg_init)
            val ownCert = Memory(MbedtlsSizeOf.mbedtls_x509_crt).also(MbedtlsApi::mbedtls_x509_crt_init)
            val caCert = Memory(MbedtlsSizeOf.mbedtls_x509_crt).also(MbedtlsApi::mbedtls_x509_crt_init)
            val pkey = Memory(MbedtlsSizeOf.mbedtls_pk_context).also(MbedtlsApi::mbedtls_pk_init)
            var cipherSuiteIds: Memory? = null

            val endpointType = if (isServer) MbedtlsApi.MBEDTLS_SSL_IS_SERVER else MbedtlsApi.MBEDTLS_SSL_IS_CLIENT
            mbedtls_ssl_config_defaults(sslConfig, endpointType, MbedtlsApi.MBEDTLS_SSL_TRANSPORT_DATAGRAM, MbedtlsApi.MBEDTLS_SSL_PRESET_DEFAULT).verify()
            mbedtls_ssl_conf_min_version(sslConfig, MbedtlsApi.MBEDTLS_SSL_MAJOR_VERSION_3, MbedtlsApi.MBEDTLS_SSL_MINOR_VERSION_3)

            mbedtls_ctr_drbg_seed(ctrDrbg, MbedtlsApi.mbedtls_entropy_func, entropy, Pointer.NULL, 0).verify()
            mbedtls_ssl_conf_rng(sslConfig, mbedtls_ctr_drbg_random, ctrDrbg)

            // cookies
            var cookieCtx: Memory? = null
            if (!isServer) {
                mbedtls_ssl_conf_dtls_cookies(sslConfig, null, null, null)
            } else {
                cookieCtx = Memory(MbedtlsSizeOf.mbedtls_ssl_cookie_ctx).also(MbedtlsApi::mbedtls_ssl_cookie_init)
                mbedtls_ssl_cookie_setup(cookieCtx, mbedtls_ctr_drbg_random, ctrDrbg).verify()
                mbedtls_ssl_conf_dtls_cookies(sslConfig, mbedtls_ssl_cookie_write, mbedtls_ssl_cookie_check, cookieCtx)
            }

            // PSK
            if (pskSecret != null && pskId != null) {
                mbedtls_ssl_conf_psk(sslConfig, pskSecret, pskSecret.size, pskId, pskId.size).verify()
            }

            mbedtls_ssl_conf_authmode(sslConfig, if (requiredAuthMode) MbedtlsApi.MBEDTLS_SSL_VERIFY_REQUIRED else MbedtlsApi.MBEDTLS_SSL_VERIFY_NONE)
            if (cipherSuites.isNotEmpty()) {
                cipherSuiteIds = mapCipherSuites(cipherSuites)
                mbedtls_ssl_conf_ciphersuites(sslConfig, cipherSuiteIds).verify()
            }

            if (cidSupplier != EmptyCidSupplier) {
                mbedtls_ssl_conf_cid(sslConfig, cidSupplier.next().size, 0)
            }

            // Trusted certificates
            for (cert in trustedCerts) {
                val certDer = cert.encoded
                mbedtls_x509_crt_parse_der(caCert, certDer, certDer.size).verify()
            }
            mbedtls_ssl_conf_ca_chain(sslConfig, caCert, Pointer.NULL)

            // Own certificate
            for (cert in ownCertChain) {
                val certDer = cert.encoded
                mbedtls_x509_crt_parse_der(ownCert, certDer, certDer.size).verify()
            }
            if (privateKey != null) {
                mbedtls_pk_parse_key(pkey, privateKey.encoded, privateKey.encoded.size, Pointer.NULL, 0, mbedtls_ctr_drbg_random, ctrDrbg)
                mbedtls_ssl_conf_own_cert(sslConfig, ownCert, pkey)
            }

            // retransmission timeout
            mbedtls_ssl_conf_handshake_timeout(sslConfig, retransmitMin.toMillis().toInt(), retransmitMax.toMillis().toInt())

            // Logging
            mbedtls_ssl_conf_dbg(sslConfig, LogCallback, Pointer.NULL)

            return SslConfig(sslConfig, cidSupplier, mtu) {
                mbedtls_ssl_config_free(sslConfig)
                mbedtls_entropy_free(entropy)
                mbedtls_ctr_drbg_free(ctrDrbg)
                mbedtls_pk_free(pkey)
                mbedtls_x509_crt_free(ownCert)
                mbedtls_x509_crt_free(caCert)
                cookieCtx?.also(::mbedtls_ssl_cookie_free)
                cipherSuiteIds?.also { it.clear() }
            }
        }

        private fun mapCipherSuites(cipherSuites: List<String>): Memory {
            val ids = cipherSuites.map(Companion::getCipherSuiteId).toIntArray()

            val cipherSuiteList = Memory(((ids.size + 1) * 4).toLong())
            cipherSuiteList.write(0, ids, 0, ids.size)
            cipherSuiteList.setInt(cipherSuiteList.size() - 4, 0)
            return cipherSuiteList
        }

        private fun getCipherSuiteId(cipherSuite: String): Int {
            val id = mbedtls_ssl_get_ciphersuite_id(cipherSuite)
            if (id <= 0) throw SslException("Unknown cipher-suite: $cipherSuite")
            return id
        }
    }

    private object LogCallback : Callback {
        private val logger = LoggerFactory.getLogger(javaClass)
        fun callback(ctx: Pointer?, debugLevel: Int, fileName: String, lineNumber: Int, message: String?) {
            when (debugLevel) {
                1 -> logger.warn("[mbedtls {}:{}] {} ", fileName.substringAfterLast('/'), lineNumber, message?.trim())
                2 -> logger.debug("[mbedtls {}:{}] {}", fileName.substringAfterLast('/'), lineNumber, message?.trim())
                else -> logger.trace("[mbedtls {}:{}] {}", fileName.substringAfterLast('/'), lineNumber, message?.trim())
            }
        }
    }

    private object NoOpsSetDelayCallback : Callback {
        fun callback(data: Pointer?, intermediateMs: Int, finalMs: Int) {
            // do nothing
        }
    }

    private object NoOpsGetDelayCallback : Callback {
        fun callback(data: Pointer?): Int {
            return 1
        }
    }
}
