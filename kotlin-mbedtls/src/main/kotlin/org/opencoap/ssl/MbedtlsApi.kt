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

@file:Suppress("FunctionNaming", "TooManyFunctions")

package org.opencoap.ssl

import org.slf4j.LoggerFactory
import java.lang.foreign.Arena
import java.lang.foreign.FunctionDescriptor
import java.lang.foreign.Linker
import java.lang.foreign.MemorySegment
import java.lang.foreign.SymbolLookup
import java.lang.foreign.ValueLayout
import java.lang.invoke.MethodHandle
import java.nio.ByteBuffer

/*
Defines mbedtls native functions that can be used from the jvm via the Foreign Function & Memory API.

Each native function is exposed as a cached MethodHandle downcall with an explicit FunctionDescriptor and is
dispatched with invokeExact. ABI widths mirror the previous JNA signatures: native `size_t` parameters are
declared as 32-bit `int` (JAVA_INT) to minimize change. The wrappers keep Kotlin-friendly signatures and
convert ByteArray/String/ByteBuffer arguments into off-heap MemorySegments on a per-call confined Arena.
 */
internal object MbedtlsApi {

    private val linker: Linker = Linker.nativeLinker()
    private val lookup: SymbolLookup = MbedtlsNativeLoader.lookup

    private val ADDRESS = ValueLayout.ADDRESS
    private val INT = ValueLayout.JAVA_INT
    private val BYTE = ValueLayout.JAVA_BYTE

    private fun handle(name: String, descriptor: FunctionDescriptor): MethodHandle {
        val symbol = lookup.find(name).orElseThrow { UnsatisfiedLinkError("Native symbol not found: $name") }
        return linker.downcallHandle(symbol, descriptor)
    }

    fun symbol(name: String): MemorySegment = lookup.find(name).orElseThrow { UnsatisfiedLinkError("Native symbol not found: $name") }

    private fun Arena.copyOf(bytes: ByteArray): MemorySegment {
        val segment = allocate(if (bytes.isEmpty()) 1L else bytes.size.toLong())
        if (bytes.isNotEmpty()) MemorySegment.copy(bytes, 0, segment, BYTE, 0L, bytes.size)
        return segment
    }

    // ----- mbedtls/ssl.h -----

    private val H_conf_authmode = handle("mbedtls_ssl_conf_authmode", FunctionDescriptor.ofVoid(ADDRESS, INT))
    fun mbedtls_ssl_conf_authmode(mbedtlsSslConfig: MemorySegment, authmode: Int) {
        H_conf_authmode.invokeExact(mbedtlsSslConfig, authmode)
    }

    private val H_conf_ciphersuites = handle("mbedtls_ssl_conf_ciphersuites", FunctionDescriptor.ofVoid(ADDRESS, ADDRESS))
    fun mbedtls_ssl_conf_ciphersuites(sslConfig: MemorySegment, cipherSuiteIds: MemorySegment) {
        H_conf_ciphersuites.invokeExact(sslConfig, cipherSuiteIds)
    }

    private val H_conf_dbg = handle("mbedtls_ssl_conf_dbg", FunctionDescriptor.ofVoid(ADDRESS, ADDRESS, ADDRESS))
    fun mbedtls_ssl_conf_dbg(mbedtlsSslConfig: MemorySegment, callback: MemorySegment, pDbg: MemorySegment) {
        H_conf_dbg.invokeExact(mbedtlsSslConfig, callback, pDbg)
    }

    private val H_conf_dtls_cookies = handle("mbedtls_ssl_conf_dtls_cookies", FunctionDescriptor.ofVoid(ADDRESS, ADDRESS, ADDRESS, ADDRESS))
    fun mbedtls_ssl_conf_dtls_cookies(mbedtlsSslConfig: MemorySegment, fCookieWrite: MemorySegment, fCookieCheck: MemorySegment, pCookie: MemorySegment) {
        H_conf_dtls_cookies.invokeExact(mbedtlsSslConfig, fCookieWrite, fCookieCheck, pCookie)
    }

    private val H_conf_handshake_timeout = handle("mbedtls_ssl_conf_handshake_timeout", FunctionDescriptor.ofVoid(ADDRESS, INT, INT))
    fun mbedtls_ssl_conf_handshake_timeout(sslConfig: MemorySegment, min: Int, max: Int) {
        H_conf_handshake_timeout.invokeExact(sslConfig, min, max)
    }

    private val H_conf_psk = handle("mbedtls_ssl_conf_psk", FunctionDescriptor.of(INT, ADDRESS, ADDRESS, INT, ADDRESS, INT))
    fun mbedtls_ssl_conf_psk(conf: MemorySegment, psk: ByteArray, pskLen: Int, pskIdentity: ByteArray, pskIdentityLen: Int): Int = Arena.ofConfined().use { arena ->
        mbedtls_ssl_conf_psk_native(conf, arena.copyOf(psk), pskLen, arena.copyOf(pskIdentity), pskIdentityLen)
    }

    private fun mbedtls_ssl_conf_psk_native(conf: MemorySegment, psk: MemorySegment, pskLen: Int, pskIdentity: MemorySegment, pskIdentityLen: Int): Int = H_conf_psk.invokeExact(conf, psk, pskLen, pskIdentity, pskIdentityLen) as Int

    private val H_config_defaults = handle("mbedtls_ssl_config_defaults", FunctionDescriptor.of(INT, ADDRESS, INT, INT, INT))
    fun mbedtls_ssl_config_defaults(mbedtlsSslConfig: MemorySegment, endpoint: Int, transport: Int, preset: Int): Int = H_config_defaults.invokeExact(mbedtlsSslConfig, endpoint, transport, preset) as Int

    private val H_config_free = handle("mbedtls_ssl_config_free", FunctionDescriptor.ofVoid(ADDRESS))
    fun mbedtls_ssl_config_free(sslConfig: MemorySegment) {
        H_config_free.invokeExact(sslConfig)
    }

    private val H_config_init = handle("mbedtls_ssl_config_init", FunctionDescriptor.ofVoid(ADDRESS))
    fun mbedtls_ssl_config_init(sslConfig: MemorySegment) {
        H_config_init.invokeExact(sslConfig)
    }

    private val H_close_notify = handle("mbedtls_ssl_close_notify", FunctionDescriptor.of(INT, ADDRESS))
    fun mbedtls_ssl_close_notify(sslContext: MemorySegment): Int = H_close_notify.invokeExact(sslContext) as Int

    private val H_ssl_free = handle("mbedtls_ssl_free", FunctionDescriptor.ofVoid(ADDRESS))
    fun mbedtls_ssl_free(sslContext: MemorySegment) {
        H_ssl_free.invokeExact(sslContext)
    }

    private val H_get_ciphersuite = handle("mbedtls_ssl_get_ciphersuite", FunctionDescriptor.of(ADDRESS, ADDRESS))
    fun mbedtls_ssl_get_ciphersuite(sslContext: MemorySegment): String = (H_get_ciphersuite.invokeExact(sslContext) as MemorySegment).readCString()

    private val H_get_ciphersuite_id = handle("mbedtls_ssl_get_ciphersuite_id", FunctionDescriptor.of(INT, ADDRESS))
    fun mbedtls_ssl_get_ciphersuite_id(name: String): Int = Arena.ofConfined().use { arena -> mbedtls_ssl_get_ciphersuite_id_native(arena.allocateFrom(name)) }

    private fun mbedtls_ssl_get_ciphersuite_id_native(name: MemorySegment): Int = H_get_ciphersuite_id.invokeExact(name) as Int

    private val H_handshake = handle("mbedtls_ssl_handshake", FunctionDescriptor.of(INT, ADDRESS))
    fun mbedtls_ssl_handshake(sslContext: MemorySegment): Int = H_handshake.invokeExact(sslContext) as Int

    private val H_ssl_init = handle("mbedtls_ssl_init", FunctionDescriptor.ofVoid(ADDRESS))
    fun mbedtls_ssl_init(sslContext: MemorySegment) {
        H_ssl_init.invokeExact(sslContext)
    }

    private val H_ssl_read = handle("mbedtls_ssl_read", FunctionDescriptor.of(INT, ADDRESS, ADDRESS, INT))
    fun mbedtls_ssl_read(sslContext: MemorySegment, buf: ByteBuffer, len: Int): Int {
        if (buf.isDirect) {
            return mbedtls_ssl_read_native(sslContext, MemorySegment.ofBuffer(buf), len)
        }
        return Arena.ofConfined().use { arena ->
            val segment = arena.allocate(len.coerceAtLeast(1).toLong())
            val ret = mbedtls_ssl_read_native(sslContext, segment, len)
            if (ret > 0) {
                val pos = buf.position()
                MemorySegment.copy(segment, BYTE, 0L, buf.array(), buf.arrayOffset() + pos, ret)
            }
            ret
        }
    }

    private fun mbedtls_ssl_read_native(sslContext: MemorySegment, buf: MemorySegment, len: Int): Int = H_ssl_read.invokeExact(sslContext, buf, len) as Int

    private val H_set_client_transport_id = handle("mbedtls_ssl_set_client_transport_id", FunctionDescriptor.of(INT, ADDRESS, ADDRESS, INT))
    fun mbedtls_ssl_set_client_transport_id(sslContext: MemorySegment, info: String, ilen: Int): Int = Arena.ofConfined().use { arena -> mbedtls_ssl_set_client_transport_id_native(sslContext, arena.allocateFrom(info), ilen) }

    private fun mbedtls_ssl_set_client_transport_id_native(sslContext: MemorySegment, info: MemorySegment, ilen: Int): Int = H_set_client_transport_id.invokeExact(sslContext, info, ilen) as Int

    private val H_set_bio = handle("mbedtls_ssl_set_bio", FunctionDescriptor.ofVoid(ADDRESS, ADDRESS, ADDRESS, ADDRESS, ADDRESS))
    fun mbedtls_ssl_set_bio(sslContext: MemorySegment, pBaseIO: MemorySegment, fSend: MemorySegment, fRecv: MemorySegment, fRecvTimeout: MemorySegment) {
        H_set_bio.invokeExact(sslContext, pBaseIO, fSend, fRecv, fRecvTimeout)
    }

    private val H_set_timer_cb = handle("mbedtls_ssl_set_timer_cb", FunctionDescriptor.ofVoid(ADDRESS, ADDRESS, ADDRESS, ADDRESS))
    fun mbedtls_ssl_set_timer_cb(ssl: MemorySegment, timer: MemorySegment, timingSetDelay: MemorySegment, timingGetDelay: MemorySegment) {
        H_set_timer_cb.invokeExact(ssl, timer, timingSetDelay, timingGetDelay)
    }

    private val H_ssl_setup = handle("mbedtls_ssl_setup", FunctionDescriptor.of(INT, ADDRESS, ADDRESS))
    fun mbedtls_ssl_setup(sslContext: MemorySegment, mbedtlsSslConfig: MemorySegment): Int = H_ssl_setup.invokeExact(sslContext, mbedtlsSslConfig) as Int

    private val H_ssl_write = handle("mbedtls_ssl_write", FunctionDescriptor.of(INT, ADDRESS, ADDRESS, INT))
    fun mbedtls_ssl_write(sslContext: MemorySegment, buf: ByteBuffer, len: Int): Int {
        if (buf.isDirect) {
            return mbedtls_ssl_write_native(sslContext, MemorySegment.ofBuffer(buf), len)
        }
        return Arena.ofConfined().use { arena ->
            val segment = arena.allocate(len.coerceAtLeast(1).toLong())
            MemorySegment.copy(buf.array(), buf.arrayOffset() + buf.position(), segment, BYTE, 0L, len)
            mbedtls_ssl_write_native(sslContext, segment, len)
        }
    }

    private fun mbedtls_ssl_write_native(sslContext: MemorySegment, buf: MemorySegment, len: Int): Int = H_ssl_write.invokeExact(sslContext, buf, len) as Int

    private val H_conf_cid = handle("mbedtls_ssl_conf_cid", FunctionDescriptor.of(INT, ADDRESS, INT, INT))
    fun mbedtls_ssl_conf_cid(mbedtlsSslConfig: MemorySegment, len: Int, ignoreOtherCids: Int): Int = H_conf_cid.invokeExact(mbedtlsSslConfig, len, ignoreOtherCids) as Int

    private val H_set_cid = handle("mbedtls_ssl_set_cid", FunctionDescriptor.of(INT, ADDRESS, INT, ADDRESS, INT))
    fun mbedtls_ssl_set_cid(sslContext: MemorySegment, enable: Int, ownCid: ByteArray, ownCidLen: Int): Int = Arena.ofConfined().use { arena -> mbedtls_ssl_set_cid_native(sslContext, enable, arena.copyOf(ownCid), ownCidLen) }

    private fun mbedtls_ssl_set_cid_native(sslContext: MemorySegment, enable: Int, ownCid: MemorySegment, ownCidLen: Int): Int = H_set_cid.invokeExact(sslContext, enable, ownCid, ownCidLen) as Int

    private val H_get_peer_cid = handle("mbedtls_ssl_get_peer_cid", FunctionDescriptor.of(INT, ADDRESS, ADDRESS, ADDRESS, ADDRESS))
    fun mbedtls_ssl_get_peer_cid(sslContext: MemorySegment, enabled: MemorySegment, peerCid: MemorySegment, peerCidLen: MemorySegment): Int = H_get_peer_cid.invokeExact(sslContext, enabled, peerCid, peerCidLen) as Int

    private val H_context_save = handle("mbedtls_ssl_context_save", FunctionDescriptor.of(INT, ADDRESS, ADDRESS, INT, ADDRESS))
    fun mbedtls_ssl_context_save(sslContext: MemorySegment, buf: ByteArray, bufLen: Int, outputLen: ByteArray): Int = Arena.ofConfined().use { arena ->
        val bufSeg = arena.allocate(bufLen.toLong())
        val olenSeg = arena.allocate(ValueLayout.JAVA_LONG)
        val ret = mbedtls_ssl_context_save_native(sslContext, bufSeg, bufLen, olenSeg)
        MemorySegment.copy(bufSeg, BYTE, 0L, buf, 0, bufLen)
        // olen is a size_t; copy its low bytes into the caller's output buffer (mirrors the JNA layout)
        MemorySegment.copy(olenSeg, BYTE, 0L, outputLen, 0, outputLen.size)
        ret
    }

    private fun mbedtls_ssl_context_save_native(sslContext: MemorySegment, buf: MemorySegment, bufLen: Int, outputLen: MemorySegment): Int = H_context_save.invokeExact(sslContext, buf, bufLen, outputLen) as Int

    private val H_context_load = handle("mbedtls_ssl_context_load", FunctionDescriptor.of(INT, ADDRESS, ADDRESS, INT))
    fun mbedtls_ssl_context_load(sslContext: MemorySegment, buf: ByteArray, len: Int): Int = Arena.ofConfined().use { arena -> mbedtls_ssl_context_load_native(sslContext, arena.copyOf(buf), len) }

    private fun mbedtls_ssl_context_load_native(sslContext: MemorySegment, buf: MemorySegment, len: Int): Int = H_context_load.invokeExact(sslContext, buf, len) as Int

    private val H_check_record = handle("mbedtls_ssl_check_record", FunctionDescriptor.of(INT, ADDRESS, ADDRESS, INT))
    fun mbedtls_ssl_check_record(sslContext: MemorySegment, buf: MemorySegment, bufLen: Int): Int = H_check_record.invokeExact(sslContext, buf, bufLen) as Int

    private val H_conf_ca_chain = handle("mbedtls_ssl_conf_ca_chain", FunctionDescriptor.ofVoid(ADDRESS, ADDRESS, ADDRESS))
    fun mbedtls_ssl_conf_ca_chain(sslConfig: MemorySegment, caChain: MemorySegment, caCrl: MemorySegment) {
        H_conf_ca_chain.invokeExact(sslConfig, caChain, caCrl)
    }

    private val H_conf_own_cert = handle("mbedtls_ssl_conf_own_cert", FunctionDescriptor.of(INT, ADDRESS, ADDRESS, ADDRESS))
    fun mbedtls_ssl_conf_own_cert(sslConfig: MemorySegment, ownCert: MemorySegment, pkKey: MemorySegment): Int = H_conf_own_cert.invokeExact(sslConfig, ownCert, pkKey) as Int

    private val H_set_mtu = handle("mbedtls_ssl_set_mtu", FunctionDescriptor.ofVoid(ADDRESS, INT))
    fun mbedtls_ssl_set_mtu(sslContext: MemorySegment, mtu: Int) {
        H_set_mtu.invokeExact(sslContext, mtu)
    }

    private val H_get_peer_cert = handle("mbedtls_ssl_get_peer_cert", FunctionDescriptor.of(ADDRESS, ADDRESS))
    fun mbedtls_ssl_get_peer_cert(sslContext: MemorySegment): MemorySegment? {
        val ptr = H_get_peer_cert.invokeExact(sslContext) as MemorySegment
        return if (ptr.address() == 0L) null else ptr
    }

    private val H_set_hostname = handle("mbedtls_ssl_set_hostname", FunctionDescriptor.of(INT, ADDRESS, ADDRESS))
    fun mbedtls_ssl_set_hostname(sslContext: MemorySegment, hostname: String?): Int = Arena.ofConfined().use { arena ->
        val hostnameSeg = if (hostname == null) MemorySegment.NULL else arena.allocateFrom(hostname)
        mbedtls_ssl_set_hostname_native(sslContext, hostnameSeg)
    }

    private fun mbedtls_ssl_set_hostname_native(sslContext: MemorySegment, hostname: MemorySegment): Int = H_set_hostname.invokeExact(sslContext, hostname) as Int

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
    const val MBEDTLS_ERR_NET_RECV_FAILED = -0x004C
    const val MBEDTLS_ERR_NET_SEND_FAILED = -0x004E

    // mbedtls/debug.h
    private val H_debug_set_threshold = handle("mbedtls_debug_set_threshold", FunctionDescriptor.ofVoid(INT))
    fun mbedtls_debug_set_threshold(threshold: Int) {
        H_debug_set_threshold.invokeExact(threshold)
    }

    // mbedtls/ssl_cookie.h
    private val H_cookie_init = handle("mbedtls_ssl_cookie_init", FunctionDescriptor.ofVoid(ADDRESS))
    fun mbedtls_ssl_cookie_init(cookieCtx: MemorySegment) {
        H_cookie_init.invokeExact(cookieCtx)
    }

    private val H_cookie_free = handle("mbedtls_ssl_cookie_free", FunctionDescriptor.ofVoid(ADDRESS))
    fun mbedtls_ssl_cookie_free(cookieCtx: MemorySegment) {
        H_cookie_free.invokeExact(cookieCtx)
    }

    private val H_cookie_setup = handle("mbedtls_ssl_cookie_setup", FunctionDescriptor.of(INT, ADDRESS))
    fun mbedtls_ssl_cookie_setup(cookieCtx: MemorySegment): Int = H_cookie_setup.invokeExact(cookieCtx) as Int

    // Passed by address (no upcall): the native function pointers themselves.
    val mbedtls_ssl_cookie_write: MemorySegment = symbol("mbedtls_ssl_cookie_write")
    val mbedtls_ssl_cookie_check: MemorySegment = symbol("mbedtls_ssl_cookie_check")

    // -------------------------

    init {
        configureLogThreshold()
    }

    internal fun Int.verify(): Int {
        if (this >= 0) return this

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
        private val H_pk_init = handle("mbedtls_pk_init", FunctionDescriptor.ofVoid(ADDRESS))
        fun mbedtls_pk_init(ctx: MemorySegment) {
            H_pk_init.invokeExact(ctx)
        }

        private val H_pk_free = handle("mbedtls_pk_free", FunctionDescriptor.ofVoid(ADDRESS))
        fun mbedtls_pk_free(ctx: MemorySegment) {
            H_pk_free.invokeExact(ctx)
        }

        private val H_pk_parse_key = handle("mbedtls_pk_parse_key", FunctionDescriptor.of(INT, ADDRESS, ADDRESS, INT, ADDRESS, INT))
        fun mbedtls_pk_parse_key(ctx: MemorySegment, key: ByteArray, keyLen: Int, pwd: MemorySegment, pwdLen: Int): Int = Arena.ofConfined().use { arena -> mbedtls_pk_parse_key_native(ctx, arena.copyOf(key), keyLen, pwd, pwdLen) }

        private fun mbedtls_pk_parse_key_native(ctx: MemorySegment, key: MemorySegment, keyLen: Int, pwd: MemorySegment, pwdLen: Int): Int = H_pk_parse_key.invokeExact(ctx, key, keyLen, pwd, pwdLen) as Int

        // psa/crypto.h
        private val H_psa_crypto_init = handle("psa_crypto_init", FunctionDescriptor.of(INT))
        fun psa_crypto_init(): Int = H_psa_crypto_init.invokeExact() as Int
    }

    internal object X509 {
        // mbedtls/x509_crt.h
        private val H_crt_init = handle("mbedtls_x509_crt_init", FunctionDescriptor.ofVoid(ADDRESS))
        fun mbedtls_x509_crt_init(cert: MemorySegment) {
            H_crt_init.invokeExact(cert)
        }

        private val H_crt_free = handle("mbedtls_x509_crt_free", FunctionDescriptor.ofVoid(ADDRESS))
        fun mbedtls_x509_crt_free(cert: MemorySegment) {
            H_crt_free.invokeExact(cert)
        }

        private val H_crt_parse_der = handle("mbedtls_x509_crt_parse_der", FunctionDescriptor.of(INT, ADDRESS, ADDRESS, INT))
        fun mbedtls_x509_crt_parse_der(chain: MemorySegment, buf: ByteArray, len: Int): Int = Arena.ofConfined().use { arena -> mbedtls_x509_crt_parse_der_native(chain, arena.copyOf(buf), len) }

        private fun mbedtls_x509_crt_parse_der_native(chain: MemorySegment, buf: MemorySegment, len: Int): Int = H_crt_parse_der.invokeExact(chain, buf, len) as Int

        // mbedtls/error.h
        private val H_strerror = handle("mbedtls_strerror", FunctionDescriptor.ofVoid(INT, ADDRESS, INT))
        fun mbedtls_strerror(errnum: Int, buffer: MemorySegment, buflen: Int) {
            H_strerror.invokeExact(errnum, buffer, buflen)
        }
    }
}

private const val MAX_C_STRING_BYTES = 4096L

internal fun MemorySegment.readCString(): String {
    if (address() == 0L) return ""
    return reinterpret(MAX_C_STRING_BYTES).getString(0L)
}
