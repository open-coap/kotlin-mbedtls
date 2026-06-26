/*
 * Copyright (c) 2022-2024 kotlin-mbedtls contributors (https://github.com/open-coap/kotlin-mbedtls)
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

import org.opencoap.ssl.MbedtlsApi.MBEDTLS_ERR_SSL_UNEXPECTED_RECORD
import org.opencoap.ssl.MbedtlsApi.mbedtls_ssl_close_notify
import org.opencoap.ssl.MbedtlsApi.mbedtls_ssl_context_save
import org.opencoap.ssl.MbedtlsApi.mbedtls_ssl_free
import org.opencoap.ssl.MbedtlsApi.mbedtls_ssl_get_ciphersuite
import org.opencoap.ssl.MbedtlsApi.mbedtls_ssl_get_peer_cert
import org.opencoap.ssl.MbedtlsApi.mbedtls_ssl_get_peer_cid
import org.opencoap.ssl.MbedtlsApi.mbedtls_ssl_handshake
import org.opencoap.ssl.MbedtlsApi.mbedtls_ssl_read
import org.opencoap.ssl.MbedtlsApi.mbedtls_ssl_write
import org.opencoap.ssl.MbedtlsApi.verify
import org.opencoap.ssl.transport.cloneToMemory
import org.opencoap.ssl.transport.toHex
import org.slf4j.LoggerFactory
import java.io.Closeable
import java.lang.foreign.Arena
import java.lang.foreign.MemorySegment
import java.lang.foreign.ValueLayout
import java.net.InetSocketAddress
import java.nio.ByteBuffer
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.time.Duration

sealed interface SslContext : Closeable {
    companion object {
        fun peekCID(size: Int, encBuffer: ByteBuffer): ByteArray? {
            val pos = encBuffer.position()
            if (encBuffer.remaining() < 11 + size) {
                // too short
                return null
            }
            if ((encBuffer.int shr 8) != 0x19fefd) {
                // not a dtls+cid packet
                encBuffer.position(pos)
                return null
            }

            val cid = ByteArray(size)

            encBuffer.position(pos + 11)
            encBuffer.get(cid)
            encBuffer.position(pos)
            return cid
        }
    }
}

class SslHandshakeContext internal constructor(
    private val conf: SslConfig, // keep in memory to prevent GC
    private val arena: Arena,
    private val sslContext: MemorySegment,
    private val cid: ByteArray?,
    private val peerAdr: InetSocketAddress,
) : SslContext {
    private val logger = LoggerFactory.getLogger(javaClass)
    val startTimestamp: Long = System.currentTimeMillis()
    var finishTimestamp: Long = 0
    private var stepTimeout: Duration = Duration.ZERO

    fun step(send: (ByteBuffer) -> Unit): SslContext = step0(null, send)
    fun step(receivedBuf: ByteBuffer, send: (ByteBuffer) -> Unit): SslContext = step0(receivedBuf, send)

    private fun step0(receivedBuf: ByteBuffer?, send: (ByteBuffer) -> Unit): SslContext {
        val ret = ReceiveCallback.invoke(receivedBuf) {
            SendCallback(send) {
                mbedtls_ssl_handshake(sslContext)
            }.also {
                stepTimeout = Duration.ofMillis(ReceiveCallback.timeout().toLong())
            }
        }

        return when (ret) {
            MbedtlsApi.MBEDTLS_ERR_SSL_WANT_READ -> return this
            MbedtlsApi.MBEDTLS_ERR_SSL_HELLO_VERIFY_REQUIRED -> throw HelloVerifyRequired
            // ownership of arena + sslContext transfers to the session; this handshake context is discarded without close()
            0 -> SslSession(conf, arena, sslContext, cid).also {
                finishTimestamp = System.currentTimeMillis()
                logger.info("[{}] DTLS connected in {}ms {}", peerAdr, finishTimestamp - startTimestamp, it)
            }

            else -> throw SslException.from(ret).also {
                finishTimestamp = System.currentTimeMillis()
                logger.debug("[{}] DTLS failed handshake: {}", peerAdr, it.message)
            }
        }
    }

    val readTimeout: Duration
        get() = stepTimeout

    private var closed = false

    override fun close() {
        if (closed) return
        closed = true
        mbedtls_ssl_free(sslContext)
        arena.close()
    }
}

class SslSession internal constructor(
    private val conf: SslConfig, // keep in memory to prevent GC
    private val arena: Arena,
    private val sslContext: MemorySegment,
    private val cid: ByteArray?,
    val reloaded: Boolean = false,
) : SslContext,
    Closeable {

    val peerCid: ByteArray? = readPeerCid()
    val ownCid: ByteArray? = if (peerCid != null) cid else null
    val peerCertificateSubject: String? = readPeerCertificateSubject()

    private fun readPeerCid(): ByteArray? = Arena.ofConfined().use { arena ->
        val mem = arena.allocate(16 + 64L) // max cid len
        // layout mirrors JNA: enabled (int) at 0, peer_cid_len (size_t) at 8, peer_cid bytes at 16
        mbedtls_ssl_get_peer_cid(sslContext, mem, mem.asSlice(16L), mem.asSlice(8L))

        if (mem.get(ValueLayout.JAVA_INT, 0L) == 0) {
            null
        } else {
            val size = mem.get(ValueLayout.JAVA_INT, 8L)
            val cidBytes = ByteArray(size)
            MemorySegment.copy(mem, ValueLayout.JAVA_BYTE, 16L, cidBytes, 0, size)
            cidBytes
        }
    }

    private fun readPeerCertificateSubject(): String? {
        val cert = mbedtls_ssl_get_peer_cert(sslContext) ?: return null
        val crt = cert.reinterpret(MbedtlsSizeOf.mbedtls_x509_crt)

        val rawOffset = MbedtlsOffsetOf.mbedtls_x509_crt__raw
        val derLen = crt.get(ValueLayout.JAVA_INT, rawOffset + MbedtlsOffsetOf.mbedtls_x509_buf__len)
        val derPointer = crt.get(ValueLayout.ADDRESS, rawOffset + MbedtlsOffsetOf.mbedtls_x509_buf__len + 8)
        val der = derPointer.reinterpret(derLen.toLong()).toArray(ValueLayout.JAVA_BYTE)

        return try {
            val factory = CertificateFactory.getInstance("X.509")
            val cert = factory.generateCertificate(der.inputStream()) as X509Certificate
            cert.subjectX500Principal.name
        } catch (ex: Exception) {
            LoggerFactory.getLogger(javaClass).warn("Could not parse peer certificate: {}", ex, ex)
            null
        }
    }

    val cipherSuite: String get() = mbedtls_ssl_get_ciphersuite(sslContext)

    fun encrypt(data: ByteBuffer): ByteBuffer = SendCallback.invoke {
        mbedtls_ssl_write(sslContext, data, data.remaining()).verify()
    } ?: ByteBuffer.allocate(0)

    fun decrypt(encBuffer: ByteBuffer, plainBuffer: ByteBuffer, send: (ByteBuffer) -> Unit) {
        // note, send function will only be use when there is retransmission
        val size = SendCallback.invoke(send) {
            ReceiveCallback(encBuffer) { sslRead(plainBuffer) }
        }
        plainBuffer.limit(size + plainBuffer.position())
    }

    fun checkRecord(encBuffer: ByteBuffer): VerificationResult = Arena.ofConfined().use { arena ->
        val memory = encBuffer.cloneToMemory(arena)
        val result = MbedtlsApi.mbedtls_ssl_check_record(sslContext, memory, memory.byteSize().toInt())
        if (result == 0 || result != MBEDTLS_ERR_SSL_UNEXPECTED_RECORD) {
            VerificationResult.Valid("Success")
        } else {
            VerificationResult.Invalid(SslException.from(result).localizedMessage)
        }
    }

    fun decrypt(encBuffer: ByteBuffer, send: (ByteBuffer) -> Unit): ByteBuffer {
        val buf = ByteBuffer.allocate(encBuffer.remaining())
        decrypt(encBuffer, buf, send)
        return buf
    }

    private fun sslRead(plainBuffer: ByteBuffer): Int {
        val ret = mbedtls_ssl_read(sslContext, plainBuffer, plainBuffer.remaining())
        return when {
            ret >= 0 -> ret
            ret == MbedtlsApi.MBEDTLS_ERR_SSL_WANT_READ -> 0
            // ret == MBEDTLS_ERR_SSL_WANT_WRITE -> 0
            else -> throw SslException.from(ret)
        }
    }

    fun saveAndClose(): ByteArray {
        val buffer = ByteArray(1280)
        val outputLen = ByteArray(4)
        mbedtls_ssl_context_save(sslContext, buffer, buffer.size, outputLen).verify()
        close()

        val size = (outputLen[0].toInt() and 0xff) + (outputLen[1].toInt() and 0xff shl 8)
        return buffer.copyOf(size)
    }

    override fun toString(): String = when {
        peerCid != null && peerCertificateSubject != null ->
            "[CID:${cid?.toHex()}, peerCID:${peerCid.toHex()}, peer-cert:$peerCertificateSubject, cipher-suite:$cipherSuite]"

        peerCid != null ->
            "[CID:${cid?.toHex()}, peerCID:${peerCid.toHex()}, cipher-suite:$cipherSuite]"

        peerCertificateSubject != null ->
            "[peer-cert:$peerCertificateSubject, cipher-suite:$cipherSuite]"

        else ->
            "[cipher-suite:$cipherSuite]"
    }

    fun closeNotify(): ByteBuffer = SendCallback {
        mbedtls_ssl_close_notify(sslContext)
    } ?: ByteBuffer.allocate(0)

    private var closed = false

    override fun close() {
        if (closed) return
        closed = true
        mbedtls_ssl_free(sslContext)
        arena.close()
    }

    sealed interface VerificationResult {
        data class Valid(val message: String) : VerificationResult
        data class Invalid(val message: String) : VerificationResult
    }
}
