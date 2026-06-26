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

import org.opencoap.ssl.MbedtlsApi.Crypto.mbedtls_pk_free
import org.opencoap.ssl.MbedtlsApi.Crypto.mbedtls_pk_parse_key
import org.opencoap.ssl.MbedtlsApi.Crypto.psa_crypto_init
import org.opencoap.ssl.MbedtlsApi.X509.mbedtls_x509_crt_free
import org.opencoap.ssl.MbedtlsApi.X509.mbedtls_x509_crt_parse_der
import org.opencoap.ssl.MbedtlsApi.mbedtls_ssl_conf_authmode
import org.opencoap.ssl.MbedtlsApi.mbedtls_ssl_conf_ca_chain
import org.opencoap.ssl.MbedtlsApi.mbedtls_ssl_conf_cid
import org.opencoap.ssl.MbedtlsApi.mbedtls_ssl_conf_ciphersuites
import org.opencoap.ssl.MbedtlsApi.mbedtls_ssl_conf_dbg
import org.opencoap.ssl.MbedtlsApi.mbedtls_ssl_conf_dtls_cookies
import org.opencoap.ssl.MbedtlsApi.mbedtls_ssl_conf_handshake_timeout
import org.opencoap.ssl.MbedtlsApi.mbedtls_ssl_conf_own_cert
import org.opencoap.ssl.MbedtlsApi.mbedtls_ssl_conf_psk
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
import org.opencoap.ssl.MbedtlsApi.mbedtls_ssl_set_hostname
import org.opencoap.ssl.MbedtlsApi.mbedtls_ssl_set_mtu
import org.opencoap.ssl.MbedtlsApi.mbedtls_ssl_set_timer_cb
import org.opencoap.ssl.MbedtlsApi.mbedtls_ssl_setup
import org.opencoap.ssl.MbedtlsApi.verify
import org.slf4j.LoggerFactory
import java.io.Closeable
import java.lang.foreign.Arena
import java.lang.foreign.FunctionDescriptor
import java.lang.foreign.Linker
import java.lang.foreign.MemorySegment
import java.lang.foreign.ValueLayout
import java.lang.invoke.MethodHandles
import java.lang.invoke.MethodType
import java.net.InetSocketAddress
import java.security.PrivateKey
import java.security.cert.X509Certificate
import java.time.Duration
import java.time.Duration.ofSeconds

private const val STRUCT_ALIGNMENT = 16L

internal fun Arena.allocStruct(size: Long): MemorySegment = allocate(size, STRUCT_ALIGNMENT)

class SslConfig(
    private val conf: MemorySegment,
    val cidSupplier: CidSupplier?,
    private val mtu: Int,
    private val close: Closeable
) : Closeable by close {
    private val logger = LoggerFactory.getLogger(javaClass)

    fun newContext(peerAddress: InetSocketAddress): SslHandshakeContext {
        val arena = Arena.ofShared()
        val sslContext = arena.allocStruct(MbedtlsSizeOf.mbedtls_ssl_context).also(MbedtlsApi::mbedtls_ssl_init)

        mbedtls_ssl_setup(sslContext, conf).verify()
        mbedtls_ssl_set_timer_cb(sslContext, MemorySegment.NULL, NoOpsSetDelayCallback.stub, NoOpsGetDelayCallback.stub)

        val cid = cidSupplier?.next()
        if (cid != null) {
            mbedtls_ssl_set_cid(sslContext, 1, cid, cid.size).verify()
        }
        mbedtls_ssl_set_mtu(sslContext, mtu)

        val clientId = peerAddress.toString()
        mbedtls_ssl_set_client_transport_id(sslContext, clientId, clientId.length)
        mbedtls_ssl_set_hostname(sslContext, null).verify()

        mbedtls_ssl_set_bio(sslContext, MemorySegment.NULL, SendCallback.stub, MemorySegment.NULL, ReceiveCallback.stub)

        return SslHandshakeContext(this, arena, sslContext, cid, peerAddress)
    }

    fun loadSession(cid: ByteArray, session: ByteArray, peerAddress: InetSocketAddress): SslSession {
        val arena = Arena.ofShared()
        val sslContext = arena.allocStruct(MbedtlsSizeOf.mbedtls_ssl_context).also(MbedtlsApi::mbedtls_ssl_init)

        mbedtls_ssl_setup(sslContext, conf).verify()
        mbedtls_ssl_context_load(sslContext, session, session.size).verify()
        mbedtls_ssl_set_bio(sslContext, MemorySegment.NULL, SendCallback.stub, MemorySegment.NULL, ReceiveCallback.stub)

        return SslSession(this, arena, sslContext, cid, true).also {
            logger.info("[{}] [{}] DTLS session reloaded {}", peerAddress, cid, it)
        }
    }

    companion object {

        @JvmStatic
        @JvmOverloads
        fun client(auth: AuthConfig, cipherSuites: List<String> = emptyList(), reqAuthentication: Boolean = true, cidSupplier: CidSupplier? = EmptyCidSupplier, retransmitMin: Duration = ofSeconds(1), retransmitMax: Duration = ofSeconds(60)): SslConfig = create(false, auth, cipherSuites, cidSupplier, reqAuthentication, 0, retransmitMin, retransmitMax)

        @JvmStatic
        @JvmOverloads
        fun server(auth: AuthConfig, cipherSuites: List<String> = emptyList(), reqAuthentication: Boolean = true, cidSupplier: CidSupplier? = EmptyCidSupplier, mtu: Int = 0, retransmitMin: Duration = ofSeconds(1), retransmitMax: Duration = ofSeconds(60)): SslConfig = create(true, auth, cipherSuites, cidSupplier, reqAuthentication, mtu, retransmitMin, retransmitMax)

        @Suppress("LongParameterList")
        private fun create(
            isServer: Boolean,
            authConfig: AuthConfig,
            cipherSuites: List<String>,
            cidSupplier: CidSupplier?,
            requiredAuthMode: Boolean = true,
            mtu: Int,
            retransmitMin: Duration,
            retransmitMax: Duration
        ): SslConfig {
            val arena = Arena.ofShared()
            val sslConfig = arena.allocStruct(MbedtlsSizeOf.mbedtls_ssl_config).also(MbedtlsApi::mbedtls_ssl_config_init)
            val ownCert = arena.allocStruct(MbedtlsSizeOf.mbedtls_x509_crt).also(MbedtlsApi.X509::mbedtls_x509_crt_init)
            val caCert = arena.allocStruct(MbedtlsSizeOf.mbedtls_x509_crt).also(MbedtlsApi.X509::mbedtls_x509_crt_init)
            val pkey = arena.allocStruct(MbedtlsSizeOf.mbedtls_pk_context).also(MbedtlsApi.Crypto::mbedtls_pk_init)

            // Initialize PSA Crypto subsystem (required in MbedTLS 4.0+)
            psa_crypto_init().verify()
            val endpointType = if (isServer) MbedtlsApi.MBEDTLS_SSL_IS_SERVER else MbedtlsApi.MBEDTLS_SSL_IS_CLIENT
            mbedtls_ssl_config_defaults(sslConfig, endpointType, MbedtlsApi.MBEDTLS_SSL_TRANSPORT_DATAGRAM, MbedtlsApi.MBEDTLS_SSL_PRESET_DEFAULT).verify()

            // cookies
            var cookieCtx: MemorySegment? = null
            if (!isServer) {
                mbedtls_ssl_conf_dtls_cookies(sslConfig, MemorySegment.NULL, MemorySegment.NULL, MemorySegment.NULL)
            } else {
                cookieCtx = arena.allocStruct(MbedtlsSizeOf.mbedtls_ssl_cookie_ctx).also(MbedtlsApi::mbedtls_ssl_cookie_init)
                mbedtls_ssl_cookie_setup(cookieCtx).verify()
                mbedtls_ssl_conf_dtls_cookies(sslConfig, mbedtls_ssl_cookie_write, mbedtls_ssl_cookie_check, cookieCtx)
            }

            mbedtls_ssl_conf_authmode(sslConfig, if (requiredAuthMode) MbedtlsApi.MBEDTLS_SSL_VERIFY_REQUIRED else MbedtlsApi.MBEDTLS_SSL_VERIFY_NONE)
            if (cipherSuites.isNotEmpty()) {
                mbedtls_ssl_conf_ciphersuites(sslConfig, mapCipherSuites(arena, cipherSuites))
            }

            if (cidSupplier != null && cidSupplier != EmptyCidSupplier) {
                mbedtls_ssl_conf_cid(sslConfig, cidSupplier.next().size, 0)
            }

            authConfig.configure(sslConfig, caCert, ownCert, pkey)

            // retransmission timeout
            mbedtls_ssl_conf_handshake_timeout(sslConfig, retransmitMin.toMillis().toInt(), retransmitMax.toMillis().toInt())

            // Logging
            mbedtls_ssl_conf_dbg(sslConfig, LogCallback.stub, MemorySegment.NULL)

            return SslConfig(sslConfig, cidSupplier, mtu) {
                mbedtls_ssl_config_free(sslConfig)
                mbedtls_pk_free(pkey)
                mbedtls_x509_crt_free(ownCert)
                mbedtls_x509_crt_free(caCert)
                cookieCtx?.also(MbedtlsApi::mbedtls_ssl_cookie_free)
                arena.close()
            }
        }

        private fun mapCipherSuites(arena: Arena, cipherSuites: List<String>): MemorySegment {
            val ids = cipherSuites.map(Companion::getCipherSuiteId).toIntArray()

            val segment = arena.allocate(((ids.size + 1) * 4).toLong())
            for (i in ids.indices) {
                segment.setAtIndex(ValueLayout.JAVA_INT, i.toLong(), ids[i])
            }
            segment.setAtIndex(ValueLayout.JAVA_INT, ids.size.toLong(), 0)
            return segment
        }

        private fun getCipherSuiteId(cipherSuite: String): Int {
            val id = mbedtls_ssl_get_ciphersuite_id(cipherSuite)
            if (id <= 0) throw SslException("Unknown cipher-suite: $cipherSuite")
            return id
        }
    }

    private object LogCallback {
        private val logger = LoggerFactory.getLogger(MbedtlsApi::class.java)

        // void f_dbg(void *ctx, int level, const char *file, int line, const char *str)
        val stub: MemorySegment = run {
            val mh = MethodHandles.lookup().findVirtual(
                LogCallback::class.java,
                "callback",
                MethodType.methodType(
                    Void.TYPE,
                    MemorySegment::class.java,
                    Int::class.javaPrimitiveType,
                    MemorySegment::class.java,
                    Int::class.javaPrimitiveType,
                    MemorySegment::class.java
                )
            ).bindTo(this)
            Linker.nativeLinker().upcallStub(
                mh,
                FunctionDescriptor.ofVoid(ValueLayout.ADDRESS, ValueLayout.JAVA_INT, ValueLayout.ADDRESS, ValueLayout.JAVA_INT, ValueLayout.ADDRESS),
                Arena.global()
            )
        }

        @Suppress("UnusedParameter")
        private fun callback(ctx: MemorySegment, debugLevel: Int, file: MemorySegment, lineNumber: Int, str: MemorySegment) {
            try {
                val fileName = file.readCString()
                val message = str.readCString()
                if (debugLevel == 1) {
                    // Introduced in MbedTLS 4.0.0: this log message should be at trace level, not warning
                    // These should be fixed in the next MbedTLS release of 4.x
                    if (message.contains("Perform PSA-based ECDH computation")) return
                    if (message.contains("<= mbedtls_ssl_check_record")) return
                    if (message.contains("=> mbedtls_ssl_check_record")) return

                    // logs when close notify is received
                    if (message.contains("mbedtls_ssl_handle_message_type() returned -30848 (-0x7880)")) return
                    if (message.contains("mbedtls_ssl_read_record() returned -30848 (-0x7880)")) return
                }

                when (debugLevel) {
                    1 -> logger.warn("[mbedtls {}:{}] {} ", fileName.substringAfterLast('/'), lineNumber, message.trim())
                    2 -> logger.debug("[mbedtls {}:{}] {}", fileName.substringAfterLast('/'), lineNumber, message.trim())
                    else -> logger.trace("[mbedtls {}:{}] {}", fileName.substringAfterLast('/'), lineNumber, message.trim())
                }
            } catch (e: Exception) {
                // never let an exception cross the native boundary
                logger.error(e.message, e)
            }
        }
    }

    private object NoOpsSetDelayCallback {
        // void f_set_timer(void *ctx, uint32_t int_ms, uint32_t fin_ms)
        val stub: MemorySegment = run {
            val mh = MethodHandles.lookup().findVirtual(
                NoOpsSetDelayCallback::class.java,
                "callback",
                MethodType.methodType(Void.TYPE, MemorySegment::class.java, Int::class.javaPrimitiveType, Int::class.javaPrimitiveType)
            ).bindTo(this)
            Linker.nativeLinker().upcallStub(
                mh,
                FunctionDescriptor.ofVoid(ValueLayout.ADDRESS, ValueLayout.JAVA_INT, ValueLayout.JAVA_INT),
                Arena.global()
            )
        }

        @Suppress("UnusedParameter")
        private fun callback(data: MemorySegment, intermediateMs: Int, finalMs: Int) {
            // do nothing
        }
    }

    private object NoOpsGetDelayCallback {
        // int f_get_timer(void *ctx)
        val stub: MemorySegment = run {
            val mh = MethodHandles.lookup().findVirtual(
                NoOpsGetDelayCallback::class.java,
                "callback",
                MethodType.methodType(Int::class.javaPrimitiveType, MemorySegment::class.java)
            ).bindTo(this)
            Linker.nativeLinker().upcallStub(
                mh,
                FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS),
                Arena.global()
            )
        }

        @Suppress("FunctionOnlyReturningConstant", "UnusedParameter")
        private fun callback(data: MemorySegment): Int = 1
    }
}

sealed interface AuthConfig {
    fun configure(sslConfig: MemorySegment, caCert: MemorySegment, ownCert: MemorySegment, pkey: MemorySegment)
}

data class PskAuth(
    val pskId: ByteArray,
    val pskSecret: ByteArray
) : AuthConfig {

    constructor(pskId: String, pskSecret: ByteArray) : this(pskId.encodeToByteArray(), pskSecret)

    override fun configure(sslConfig: MemorySegment, caCert: MemorySegment, ownCert: MemorySegment, pkey: MemorySegment) {
        mbedtls_ssl_conf_psk(sslConfig, pskSecret, pskSecret.size, pskId, pskId.size).verify()
    }
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

    override fun configure(sslConfig: MemorySegment, caCert: MemorySegment, ownCert: MemorySegment, pkey: MemorySegment) {
        for (cert in trustedCerts) {
            val certDer = cert.encoded
            mbedtls_x509_crt_parse_der(caCert, certDer, certDer.size).verify()
        }
        mbedtls_ssl_conf_ca_chain(sslConfig, caCert, MemorySegment.NULL)

        // Own certificate
        for (cert in ownCertChain) {
            val certDer = cert.encoded
            mbedtls_x509_crt_parse_der(ownCert, certDer, certDer.size).verify()
        }
        if (privateKey != null) {
            mbedtls_pk_parse_key(pkey, privateKey.encoded, privateKey.encoded.size, MemorySegment.NULL, 0)
            mbedtls_ssl_conf_own_cert(sslConfig, ownCert, pkey)
        }
    }

    companion object {
        @JvmStatic
        fun trusted(trustedCerts: List<X509Certificate>) = CertificateAuth(listOf(), null, trustedCerts.toList())

        @JvmStatic
        fun trusted(vararg trustedCerts: X509Certificate) = trusted(trustedCerts.toList())
    }
}
