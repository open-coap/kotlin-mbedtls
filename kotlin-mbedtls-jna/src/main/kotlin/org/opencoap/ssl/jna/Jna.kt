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

package org.opencoap.ssl.jna

import com.sun.jna.Memory
import com.sun.jna.Pointer
import org.opencoap.ssl.AuthConfig
import org.opencoap.ssl.Bio
import org.opencoap.ssl.CertificateAuth
import org.opencoap.ssl.ConfigSpec
import org.opencoap.ssl.Mbedtls
import org.opencoap.ssl.NativeConf
import org.opencoap.ssl.NativeContext
import org.opencoap.ssl.PskAuth
import org.opencoap.ssl.SslException
import org.opencoap.ssl.jna.MbedtlsApi.Crypto.mbedtls_pk_free
import org.opencoap.ssl.jna.MbedtlsApi.Crypto.mbedtls_pk_parse_key
import org.opencoap.ssl.jna.MbedtlsApi.Crypto.psa_crypto_init
import org.opencoap.ssl.jna.MbedtlsApi.X509.mbedtls_strerror
import org.opencoap.ssl.jna.MbedtlsApi.X509.mbedtls_x509_crt_free
import org.opencoap.ssl.jna.MbedtlsApi.X509.mbedtls_x509_crt_parse_der
import org.opencoap.ssl.jna.MbedtlsApi.mbedtls_ssl_check_record
import org.opencoap.ssl.jna.MbedtlsApi.mbedtls_ssl_close_notify
import org.opencoap.ssl.jna.MbedtlsApi.mbedtls_ssl_conf_authmode
import org.opencoap.ssl.jna.MbedtlsApi.mbedtls_ssl_conf_ca_chain
import org.opencoap.ssl.jna.MbedtlsApi.mbedtls_ssl_conf_cid
import org.opencoap.ssl.jna.MbedtlsApi.mbedtls_ssl_conf_ciphersuites
import org.opencoap.ssl.jna.MbedtlsApi.mbedtls_ssl_conf_dbg
import org.opencoap.ssl.jna.MbedtlsApi.mbedtls_ssl_conf_dtls_cookies
import org.opencoap.ssl.jna.MbedtlsApi.mbedtls_ssl_conf_handshake_timeout
import org.opencoap.ssl.jna.MbedtlsApi.mbedtls_ssl_conf_own_cert
import org.opencoap.ssl.jna.MbedtlsApi.mbedtls_ssl_conf_psk
import org.opencoap.ssl.jna.MbedtlsApi.mbedtls_ssl_config_defaults
import org.opencoap.ssl.jna.MbedtlsApi.mbedtls_ssl_config_free
import org.opencoap.ssl.jna.MbedtlsApi.mbedtls_ssl_context_load
import org.opencoap.ssl.jna.MbedtlsApi.mbedtls_ssl_context_save
import org.opencoap.ssl.jna.MbedtlsApi.mbedtls_ssl_cookie_check
import org.opencoap.ssl.jna.MbedtlsApi.mbedtls_ssl_cookie_free
import org.opencoap.ssl.jna.MbedtlsApi.mbedtls_ssl_cookie_setup
import org.opencoap.ssl.jna.MbedtlsApi.mbedtls_ssl_cookie_write
import org.opencoap.ssl.jna.MbedtlsApi.mbedtls_ssl_get_ciphersuite
import org.opencoap.ssl.jna.MbedtlsApi.mbedtls_ssl_get_ciphersuite_id
import org.opencoap.ssl.jna.MbedtlsApi.mbedtls_ssl_get_peer_cert
import org.opencoap.ssl.jna.MbedtlsApi.mbedtls_ssl_get_peer_cid
import org.opencoap.ssl.jna.MbedtlsApi.mbedtls_ssl_handshake
import org.opencoap.ssl.jna.MbedtlsApi.mbedtls_ssl_read
import org.opencoap.ssl.jna.MbedtlsApi.mbedtls_ssl_set_bio
import org.opencoap.ssl.jna.MbedtlsApi.mbedtls_ssl_set_cid
import org.opencoap.ssl.jna.MbedtlsApi.mbedtls_ssl_set_client_transport_id
import org.opencoap.ssl.jna.MbedtlsApi.mbedtls_ssl_set_hostname
import org.opencoap.ssl.jna.MbedtlsApi.mbedtls_ssl_set_mtu
import org.opencoap.ssl.jna.MbedtlsApi.mbedtls_ssl_set_timer_cb
import org.opencoap.ssl.jna.MbedtlsApi.mbedtls_ssl_setup
import org.opencoap.ssl.jna.MbedtlsApi.mbedtls_ssl_write
import org.opencoap.ssl.jna.MbedtlsApi.verify
import java.net.InetSocketAddress
import java.nio.ByteBuffer

/** JNA-backed [Mbedtls] engine. Select explicitly via `SslConfig.client(Jna, ...)` / `SslConfig.server(Jna, ...)`. */
object Jna : Mbedtls {

    init {
        // Register native error translation as soon as the engine is referenced.
        SslException.errorTranslator = { strError(it) }
    }

    override fun buildConfig(spec: ConfigSpec): NativeConf {
        val sslConfig = Memory(MbedtlsSizeOf.mbedtls_ssl_config).also(MbedtlsApi::mbedtls_ssl_config_init)
        val ownCert = Memory(MbedtlsSizeOf.mbedtls_x509_crt).also(MbedtlsApi.X509::mbedtls_x509_crt_init)
        val caCert = Memory(MbedtlsSizeOf.mbedtls_x509_crt).also(MbedtlsApi.X509::mbedtls_x509_crt_init)
        val pkey = Memory(MbedtlsSizeOf.mbedtls_pk_context).also(MbedtlsApi.Crypto::mbedtls_pk_init)
        var cipherSuiteIds: Memory? = null

        // Initialize PSA Crypto subsystem (required in MbedTLS 4.0+)
        psa_crypto_init().verify()
        val endpointType = if (spec.isServer) MbedtlsApi.MBEDTLS_SSL_IS_SERVER else MbedtlsApi.MBEDTLS_SSL_IS_CLIENT
        mbedtls_ssl_config_defaults(sslConfig, endpointType, MbedtlsApi.MBEDTLS_SSL_TRANSPORT_DATAGRAM, MbedtlsApi.MBEDTLS_SSL_PRESET_DEFAULT).verify()

        // cookies
        var cookieCtx: Memory? = null
        if (!spec.isServer) {
            mbedtls_ssl_conf_dtls_cookies(sslConfig, null, null, null)
        } else {
            cookieCtx = Memory(MbedtlsSizeOf.mbedtls_ssl_cookie_ctx).also(MbedtlsApi::mbedtls_ssl_cookie_init)
            mbedtls_ssl_cookie_setup(cookieCtx).verify()
            mbedtls_ssl_conf_dtls_cookies(sslConfig, mbedtls_ssl_cookie_write, mbedtls_ssl_cookie_check, cookieCtx)
        }

        mbedtls_ssl_conf_authmode(sslConfig, if (spec.requiredAuthMode) MbedtlsApi.MBEDTLS_SSL_VERIFY_REQUIRED else MbedtlsApi.MBEDTLS_SSL_VERIFY_NONE)
        if (spec.cipherSuites.isNotEmpty()) {
            cipherSuiteIds = mapCipherSuites(spec.cipherSuites)
            mbedtls_ssl_conf_ciphersuites(sslConfig, cipherSuiteIds)
        }

        if (spec.cidLength > 0) {
            mbedtls_ssl_conf_cid(sslConfig, spec.cidLength, 0)
        }

        configureAuth(spec.auth, sslConfig, caCert, ownCert, pkey)

        // retransmission timeout
        mbedtls_ssl_conf_handshake_timeout(sslConfig, spec.retransmitMinMillis, spec.retransmitMaxMillis)

        // Logging
        mbedtls_ssl_conf_dbg(sslConfig, LogCallback, Pointer.NULL)

        return JnaNativeConf(sslConfig) {
            mbedtls_ssl_config_free(sslConfig)
            mbedtls_pk_free(pkey)
            mbedtls_x509_crt_free(ownCert)
            mbedtls_x509_crt_free(caCert)
            cookieCtx?.also(MbedtlsApi::mbedtls_ssl_cookie_free)
            cipherSuiteIds?.also { it.clear() }
        }
    }

    private fun configureAuth(auth: AuthConfig, sslConfig: Memory, caCert: Memory, ownCert: Memory, pkey: Memory) {
        when (auth) {
            is PskAuth ->
                mbedtls_ssl_conf_psk(sslConfig, auth.pskSecret, auth.pskSecret.size, auth.pskId, auth.pskId.size).verify()

            is CertificateAuth -> {
                for (cert in auth.trustedCerts) {
                    val certDer = cert.encoded
                    mbedtls_x509_crt_parse_der(caCert, certDer, certDer.size).verify()
                }
                mbedtls_ssl_conf_ca_chain(sslConfig, caCert, Pointer.NULL)

                // Own certificate
                for (cert in auth.ownCertChain) {
                    val certDer = cert.encoded
                    mbedtls_x509_crt_parse_der(ownCert, certDer, certDer.size).verify()
                }
                val privateKey = auth.privateKey
                if (privateKey != null) {
                    mbedtls_pk_parse_key(pkey, privateKey.encoded, privateKey.encoded.size, Pointer.NULL, 0)
                    mbedtls_ssl_conf_own_cert(sslConfig, ownCert, pkey)
                }
            }
        }
    }

    override fun freeConfig(conf: NativeConf) {
        (conf as JnaNativeConf).close()
    }

    override fun newContext(conf: NativeConf, ownCid: ByteArray?, mtu: Int, peerAddress: InetSocketAddress, bio: Bio): NativeContext {
        val confMem = (conf as JnaNativeConf).conf
        val sslContext = Memory(MbedtlsSizeOf.mbedtls_ssl_context).apply(MbedtlsApi::mbedtls_ssl_init)

        mbedtls_ssl_setup(sslContext, confMem).verify()
        mbedtls_ssl_set_timer_cb(sslContext, Pointer.NULL, NoOpsSetDelayCallback, NoOpsGetDelayCallback)

        if (ownCid != null) {
            mbedtls_ssl_set_cid(sslContext, 1, ownCid, ownCid.size).verify()
        }
        mbedtls_ssl_set_mtu(sslContext, mtu)

        val clientId = peerAddress.toString()
        mbedtls_ssl_set_client_transport_id(sslContext, clientId, clientId.length)
        mbedtls_ssl_set_hostname(sslContext, null).verify()

        return wireBio(sslContext, bio)
    }

    override fun loadContext(conf: NativeConf, session: ByteArray, bio: Bio): NativeContext {
        val confMem = (conf as JnaNativeConf).conf
        val sslContext = Memory(MbedtlsSizeOf.mbedtls_ssl_context).apply(MbedtlsApi::mbedtls_ssl_init)

        mbedtls_ssl_setup(sslContext, confMem).verify()
        mbedtls_ssl_context_load(sslContext, session, session.size).verify()

        return wireBio(sslContext, bio)
    }

    private fun wireBio(sslContext: Memory, bio: Bio): JnaNativeContext {
        val send = SendCallback(bio)
        val recv = ReceiveCallback(bio)
        mbedtls_ssl_set_bio(sslContext, Pointer.NULL, send, null, recv)
        return JnaNativeContext(sslContext, bio, send, recv)
    }

    override fun handshake(ctx: NativeContext): Int = mbedtls_ssl_handshake(ctx.mem)

    override fun read(ctx: NativeContext, plainBuffer: ByteBuffer): Int = mbedtls_ssl_read(ctx.mem, plainBuffer, plainBuffer.remaining())

    override fun write(ctx: NativeContext, data: ByteBuffer): Int = mbedtls_ssl_write(ctx.mem, data, data.remaining())

    override fun checkRecord(ctx: NativeContext, encBuffer: ByteBuffer): Int {
        val memory = encBuffer.cloneToMemory()
        try {
            return mbedtls_ssl_check_record(ctx.mem, memory, memory.size().toInt())
        } finally {
            memory.close()
        }
    }

    override fun contextSave(ctx: NativeContext): ByteArray {
        val buffer = ByteArray(1280)
        val outputLen = ByteArray(4)
        mbedtls_ssl_context_save(ctx.mem, buffer, buffer.size, outputLen).verify()

        val size = (outputLen[0].toInt() and 0xff) + (outputLen[1].toInt() and 0xff shl 8)
        return buffer.copyOf(size)
    }

    override fun closeNotify(ctx: NativeContext): Int = mbedtls_ssl_close_notify(ctx.mem)

    override fun free(ctx: NativeContext) {
        MbedtlsApi.mbedtls_ssl_free(ctx.mem)
    }

    override fun getPeerCid(ctx: NativeContext): ByteArray? {
        val mem = Memory(16 + 64) // max cid len
        mbedtls_ssl_get_peer_cid(ctx.mem, mem, mem.share(16), mem.share(8))

        if (mem.getInt(0) == 0) {
            return null
        }
        val size = mem.getInt(8)
        return mem.getByteArray(16, size)
    }

    override fun getPeerCertDer(ctx: NativeContext): ByteArray? {
        val pointer = mbedtls_ssl_get_peer_cert(ctx.mem)
            ?.share(MbedtlsOffsetOf.mbedtls_x509_crt__raw)
            ?: return null

        val derLen = pointer.getInt(MbedtlsOffsetOf.mbedtls_x509_buf__len)
        val derPointer = pointer.getPointer(MbedtlsOffsetOf.mbedtls_x509_buf__len + 8)
        return derPointer.getByteArray(0, derLen)
    }

    override fun getCiphersuite(ctx: NativeContext): String = mbedtls_ssl_get_ciphersuite(ctx.mem)

    override fun strError(error: Int): String {
        val buffer = Memory(100)
        mbedtls_strerror(error, buffer, buffer.size().toInt())
        return buffer.getString(0).trim()
    }

    private fun mapCipherSuites(cipherSuites: List<String>): Memory {
        val ids = cipherSuites.map(::getCipherSuiteId).toIntArray()

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

private val NativeContext.mem: Memory get() = (this as JnaNativeContext).sslContext
