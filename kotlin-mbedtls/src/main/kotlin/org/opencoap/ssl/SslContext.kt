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
import java.nio.ByteBuffer
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.time.Duration

interface SslContext : Closeable {
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
    private val engine: Mbedtls,
    private val conf: SslConfig, // keep in memory to prevent GC
    private val ctx: NativeContext,
    private val bio: Bio,
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
        val ret = bio.withReceive(receivedBuf) {
            bio.withSend(send) {
                engine.handshake(ctx)
            }.also {
                stepTimeout = Duration.ofMillis(bio.timeout().toLong())
            }
        }

        return when (ret) {
            Mbedtls.MBEDTLS_ERR_SSL_WANT_READ -> this
            Mbedtls.MBEDTLS_ERR_SSL_HELLO_VERIFY_REQUIRED -> throw HelloVerifyRequired
            0 -> SslSession(engine, conf, ctx, bio, cid).also {
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
        engine.free(ctx)
    }
}

class SslSession internal constructor(
    private val engine: Mbedtls,
    private val conf: SslConfig, // keep in memory to prevent GC
    private val ctx: NativeContext,
    private val bio: Bio,
    private val cid: ByteArray?,
    val reloaded: Boolean = false,
) : SslContext {

    val peerCid: ByteArray? = engine.getPeerCid(ctx)
    val ownCid: ByteArray? = if (peerCid != null) cid else null
    val peerCertificateSubject: String? = readPeerCertificateSubject()

    private fun readPeerCertificateSubject(): String? {
        val der = engine.getPeerCertDer(ctx) ?: return null

        return try {
            val factory = CertificateFactory.getInstance("X.509")
            val cert = factory.generateCertificate(der.inputStream()) as X509Certificate
            cert.subjectX500Principal.name
        } catch (ex: Exception) {
            LoggerFactory.getLogger(javaClass).warn("Could not parse peer certificate: {}", ex, ex)
            null
        }
    }

    val cipherSuite: String get() = engine.getCiphersuite(ctx)

    fun encrypt(data: ByteBuffer): ByteBuffer = bio.captureSend {
        engine.write(ctx, data).verify()
    } ?: ByteBuffer.allocate(0)

    fun decrypt(encBuffer: ByteBuffer, plainBuffer: ByteBuffer, send: (ByteBuffer) -> Unit) {
        // note, send function will only be used when there is retransmission
        val size = bio.withSend(send) {
            bio.withReceive(encBuffer) { sslRead(plainBuffer) }
        }
        plainBuffer.limit(size + plainBuffer.position())
    }

    fun checkRecord(encBuffer: ByteBuffer): VerificationResult {
        val result = engine.checkRecord(ctx, encBuffer)
        return if (result == 0 || result != Mbedtls.MBEDTLS_ERR_SSL_UNEXPECTED_RECORD) {
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
        val ret = engine.read(ctx, plainBuffer)
        return when {
            ret >= 0 -> ret
            ret == Mbedtls.MBEDTLS_ERR_SSL_WANT_READ -> 0
            // ret == MBEDTLS_ERR_SSL_WANT_WRITE -> 0
            else -> throw SslException.from(ret)
        }
    }

    fun saveAndClose(): ByteArray {
        val data = engine.contextSave(ctx)
        close()
        return data
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

    fun closeNotify(): ByteBuffer = bio.captureSend {
        engine.closeNotify(ctx)
    } ?: ByteBuffer.allocate(0)

    override fun close() {
        engine.free(ctx)
    }

    sealed interface VerificationResult {
        data class Valid(val message: String) : VerificationResult
        data class Invalid(val message: String) : VerificationResult
    }
}
