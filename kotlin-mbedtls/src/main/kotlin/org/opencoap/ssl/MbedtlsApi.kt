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

@file:Suppress("FunctionNaming")

package org.opencoap.ssl

import com.sun.jna.Callback
import com.sun.jna.Function
import com.sun.jna.Memory
import com.sun.jna.Native
import com.sun.jna.NativeLibrary
import com.sun.jna.Pointer
import org.slf4j.LoggerFactory
import java.nio.ByteBuffer

/*
Defines mbedtls native functions that can be used from jvm.
 */
internal object MbedtlsApi {

    // private val libraryName = javaClass.classLoader.getResourceAsStream("mbedtls.properties").use { resource ->
    //     Properties().apply { load(resource) }.let { props ->
    //         val mbedtlsVersion = props.getProperty("mbedtlsVersion")
    //         if (Platform.isWindows()) "libmbedtls-$mbedtlsVersion" else "mbedtls-$mbedtlsVersion"
    //     }
    // }

    private val LIB_MBEDTLS = NativeLibrary.getInstance("libmbedtls.so.4.0.0")
    private val LIB_MBEDCRYPTO = NativeLibrary.getInstance("libmbedcrypto.so.4.0.0")
    private val LIB_MBEDX509 = NativeLibrary.getInstance("libmbedx509.so.4.0.0")

    init {
        Native.register(LIB_MBEDTLS)
        Native.register(Crypto::class.java, LIB_MBEDCRYPTO)
        Native.register(X509::class.java, LIB_MBEDX509)

        configureLogThreshold()
    }

    // mbedtls/ssl.h
    external fun mbedtls_ssl_conf_authmode(mbedtlsSslConfig: Pointer, authmode: Int)
    external fun mbedtls_ssl_conf_ciphersuites(sslConfig: Pointer, cipherSuiteIds: Memory)
    external fun mbedtls_ssl_conf_dbg(mbedtlsSslConfig: Pointer, callback: Callback, pDbg: Pointer?)
    external fun mbedtls_ssl_conf_dtls_cookies(mbedtlsSslConfig: Pointer, fCookieWrite: Function?, fCookieCheck: Function?, pCookie: Pointer?)
    external fun mbedtls_ssl_conf_handshake_timeout(sslConfig: Pointer, min: Int, max: Int)
    external fun mbedtls_ssl_conf_psk(conf: Pointer, psk: ByteArray, pskLen: Int, pskIdentity: ByteArray, pskIdentityLen: Int): Int
    external fun mbedtls_ssl_config_defaults(mbedtlsSslConfig: Pointer, endpoint: Int, transport: Int, preset: Int): Int
    external fun mbedtls_ssl_config_free(sslContext: Pointer)
    external fun mbedtls_ssl_config_init(sslContext: Pointer)
    external fun mbedtls_ssl_close_notify(sslContext: Pointer): Int
    external fun mbedtls_ssl_free(sslContext: Pointer)
    external fun mbedtls_ssl_get_ciphersuite(sslContext: Pointer): String
    external fun mbedtls_ssl_get_ciphersuite_id(name: String): Int
    external fun mbedtls_ssl_handshake(sslContext: Pointer): Int
    external fun mbedtls_ssl_init(sslContext: Pointer)
    external fun mbedtls_ssl_read(sslContext: Pointer, buf: ByteBuffer, len: Int): Int
    external fun mbedtls_ssl_set_client_transport_id(sslContext: Pointer, info: String, ilen: Int): Int
    external fun mbedtls_ssl_set_bio(sslContext: Pointer, pBaseIO: Pointer?, fSend: Callback, fRecv: Callback?, fRecvTimeout: Callback?)
    external fun mbedtls_ssl_set_timer_cb(ssl: Pointer, timer: Pointer?, timingSetDelay: Callback, timingGetDelay: Callback)
    external fun mbedtls_ssl_setup(sslContext: Pointer, mbedtlsSslConfig: Pointer): Int
    external fun mbedtls_ssl_write(sslContext: Pointer, buf: ByteBuffer, len: Int): Int
    external fun mbedtls_ssl_conf_cid(mbedtlsSslConfig: Pointer, len: Int, ignoreOtherCids: Int): Int
    external fun mbedtls_ssl_set_cid(sslContext: Pointer, enable: Int, ownCid: ByteArray, ownCidLen: Int): Int
    external fun mbedtls_ssl_get_peer_cid(sslContext: Pointer, enabled: Pointer, peerCid: Pointer, peerCidLen: Pointer): Int
    external fun mbedtls_ssl_context_save(sslContext: Pointer, buf: ByteArray, bufLen: Int, outputLen: ByteArray): Int
    external fun mbedtls_ssl_context_load(sslContext: Pointer, buf: ByteArray, len: Int): Int
    external fun mbedtls_ssl_check_record(sslContext: Pointer, buf: Memory, bufLen: Int): Int
    external fun mbedtls_ssl_conf_ca_chain(sslConfig: Pointer, caChain: Pointer, caCrl: Pointer?)
    external fun mbedtls_ssl_conf_own_cert(sslConfig: Pointer, ownCert: Memory, pkKey: Pointer): Int
    external fun mbedtls_ssl_set_mtu(sslContext: Pointer, mtu: Int)
    external fun mbedtls_ssl_get_peer_cert(sslContext: Pointer): Pointer?
    external fun mbedtls_ssl_set_hostname(sslContext: Pointer, hostname: String?): Int
    external fun psa_crypto_init(): Int

    const val MBEDTLS_ERR_SSL_TIMEOUT = -0x6800
    const val MBEDTLS_ERR_SSL_WANT_READ = -0x6900
    const val MBEDTLS_ERR_SSL_WANT_WRITE = -0x6880
    const val MBEDTLS_ERR_SSL_HELLO_VERIFY_REQUIRED = -0x6A80
    const val MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY = -0x7880
    const val MBEDTLS_SSL_IS_CLIENT = 0
    const val MBEDTLS_SSL_IS_SERVER = 1
    const val MBEDTLS_SSL_PRESET_DEFAULT = 0
    const val MBEDTLS_SSL_TRANSPORT_DATAGRAM = 1
    const val MBEDTLS_SSL_VERIFY_NONE = 0
    const val MBEDTLS_SSL_VERIFY_REQUIRED = 2
    const val MBEDTLS_ERR_SSL_UNEXPECTED_RECORD = -0x6700

    // ----- net_sockets.h -----
    val MBEDTLS_ERR_NET_RECV_FAILED = -0x004C
    val MBEDTLS_ERR_NET_SEND_FAILED = -0x004E

    // mbedtls/debug.h
    external fun mbedtls_debug_set_threshold(threshold: Int)

    // mbedtls/ssl_cookie.h
    external fun mbedtls_ssl_cookie_init(cookieCtx: Pointer)
    external fun mbedtls_ssl_cookie_free(cookieCtx: Pointer)
    external fun mbedtls_ssl_cookie_setup(cookieCtx: Pointer): Int
    val mbedtls_ssl_cookie_write: Function = LIB_MBEDTLS.getFunction("mbedtls_ssl_cookie_write")
    val mbedtls_ssl_cookie_check: Function = LIB_MBEDTLS.getFunction("mbedtls_ssl_cookie_check")

    // -------------------------

    internal fun Int.verify(): Int {
        if (this >= 0) return this

        println(this)
        throw SslException.from(this)
    }

    private fun configureLogThreshold() {
        val logger = LoggerFactory.getLogger(javaClass)
        if (logger.isTraceEnabled) {
            mbedtls_debug_set_threshold(4)
        } else if (logger.isDebugEnabled) {
            mbedtls_debug_set_threshold(2)
        } else if (logger.isWarnEnabled) {
            mbedtls_debug_set_threshold(1)
        } else {
            mbedtls_debug_set_threshold(0)
        }
    }

    internal object Crypto {
        // mbedtls/pk.h
        external fun mbedtls_pk_init(ctx: Pointer)
        external fun mbedtls_pk_free(ctx: Pointer)
        external fun mbedtls_pk_parse_key(ctx: Pointer, key: ByteArray, keyLen: Int, pwd: Pointer?, pwdLen: Int): Int
    }

    internal object X509 {

        // mbedtls/x509_crt.h
        external fun mbedtls_x509_crt_init(cert: Pointer)
        external fun mbedtls_x509_crt_free(cert: Pointer)
        external fun mbedtls_x509_crt_parse_der(chain: Pointer, buf: ByteArray, len: Int): Int

        // mbedtls/error.h
        external fun mbedtls_strerror(errnum: Int, buffer: Pointer, buflen: Int)
    }
}
