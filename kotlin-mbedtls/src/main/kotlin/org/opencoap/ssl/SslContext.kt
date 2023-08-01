/*
 * Copyright (c) 2022-2023 kotlin-mbedtls contributors (https://github.com/open-coap/kotlin-mbedtls)
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

import com.sun.jna.Memory
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
import org.opencoap.ssl.transport.toHex
import org.slf4j.LoggerFactory
import java.io.Closeable
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
    private val sslContext: Memory,
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
            0 -> SslSession(conf, sslContext, cid).also {
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

    override fun close() {
        mbedtls_ssl_free(sslContext)
    }
}

class SslSession internal constructor(
    private val conf: SslConfig, // keep in memory to prevent GC
    private val sslContext: Memory,
    private val cid: ByteArray?,
    val reloaded: Boolean = false,
) : SslContext, Closeable {

    val peerCid: ByteArray? = readPeerCid()
    val ownCid: ByteArray? = if (peerCid != null) cid else null
    val peerCertificateSubject: String? = readPeerCertificateSubject()

    private fun readPeerCid(): ByteArray? {
        val mem = Memory(16 + 64 /* max cid len */)
        mbedtls_ssl_get_peer_cid(sslContext, mem, mem.share(16), mem.share(8))

        if (mem.getInt(0) == 0) {
            return null
        }
        val size = mem.getInt(8)

        return mem.getByteArray(16, size)
    }

    private fun readPeerCertificateSubject(): String? {
        val pointer = mbedtls_ssl_get_peer_cert(sslContext)
            ?.share(MbedtlsOffsetOf.mbedtls_x509_crt__raw)
            ?: return null

        val derLen = pointer.getInt(MbedtlsOffsetOf.mbedtls_x509_buf__len)
        val derPointer = pointer.getPointer(MbedtlsOffsetOf.mbedtls_x509_buf__len + 8)
        val der = derPointer.getByteArray(0, derLen)

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

    fun encrypt(data: ByteBuffer): ByteBuffer {
        return SendCallback.invoke {
            mbedtls_ssl_write(sslContext, data, data.remaining()).verify()
        } ?: ByteBuffer.allocate(0)
    }

    fun decrypt(encBuffer: ByteBuffer, plainBuffer: ByteBuffer, send: (ByteBuffer) -> Unit) {
        // note, send function will only be use when there is retransmission
        val size = SendCallback.invoke(send) {
            ReceiveCallback(encBuffer) { sslRead(plainBuffer) }
        }
        plainBuffer.limit(size + plainBuffer.position())
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

    override fun toString(): String {
        return when {
            peerCid != null && peerCertificateSubject != null ->
                "[CID:${cid?.toHex()}, peerCID:${peerCid.toHex()}, peer-cert:$peerCertificateSubject, cipher-suite:$cipherSuite]"

            peerCid != null ->
                "[CID:${cid?.toHex()}, peerCID:${peerCid.toHex()}, cipher-suite:$cipherSuite]"

            peerCertificateSubject != null ->
                "[peer-cert:$peerCertificateSubject, cipher-suite:$cipherSuite]"

            else ->
                "[cipher-suite:$cipherSuite]"
        }
    }

    fun closeNotify(): ByteBuffer {
        return SendCallback {
            mbedtls_ssl_close_notify(sslContext)
        } ?: ByteBuffer.allocate(0)
    }

    override fun close() {
        mbedtls_ssl_free(sslContext)
    }
}
