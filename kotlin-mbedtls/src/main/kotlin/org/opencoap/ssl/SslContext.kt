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

import com.sun.jna.Memory
import org.opencoap.ssl.MbedtlsApi.mbedtls_ssl_close_notify
import org.opencoap.ssl.MbedtlsApi.mbedtls_ssl_context_save
import org.opencoap.ssl.MbedtlsApi.mbedtls_ssl_free
import org.opencoap.ssl.MbedtlsApi.mbedtls_ssl_get_ciphersuite
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
    private var startTimestamp: Long = System.currentTimeMillis()
    private var stepTimeout: Duration = Duration.ZERO

    fun step(send: (ByteBuffer) -> Unit): SslContext {
        return step(null, send)
    }

    fun step(receivedBuf: ByteBuffer?, send: (ByteBuffer) -> Unit): SslContext {
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
            0 -> {
                SslSession(conf, sslContext, cid).also {
                    logger.info("[{}] DTLS connected in {}ms {}", peerAdr, System.currentTimeMillis() - startTimestamp, it)
                }
            }
            else -> throw SslException.from(ret).also {
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
) : SslContext, Closeable {

    val peerCid: ByteArray? = readPeerCid()
    val ownCid: ByteArray? = if (peerCid != null) cid else null

    private fun readPeerCid(): ByteArray? {
        val mem = Memory(16 + 64 /* max cid len */)
        mbedtls_ssl_get_peer_cid(sslContext, mem, mem.share(16), mem.share(8))

        if (mem.getInt(0) == 0) {
            return null
        }
        val size = mem.getInt(8)

        return mem.getByteArray(16, size)
    }

    fun getCipherSuite(): String {
        return mbedtls_ssl_get_ciphersuite(sslContext)
    }

    fun encrypt(data: ByteArray): ByteBuffer {
        val buffer = Memory(data.size.toLong())
        buffer.write(0, data, 0, data.size)

        return SendCallback {
            mbedtls_ssl_write(sslContext, buffer, data.size).verify()
        } ?: ByteBuffer.allocate(0)
    }

    fun decrypt(encBuffer: ByteBuffer): ByteArray {
        val plainBuffer = Memory(encBuffer.remaining().toLong())
        val size = ReceiveCallback(encBuffer) {
            mbedtls_ssl_read(sslContext, plainBuffer, plainBuffer.size().toInt()).verify()
        }

        return plainBuffer.getByteArray(0, size)
    }

    fun saveAndClose(): ByteArray {
        val buffer = Memory(512)
        val outputLen = Memory(8)
        mbedtls_ssl_context_save(sslContext, buffer, buffer.size().toInt(), outputLen).verify()
        close()

        return buffer.getByteArray(0, outputLen.getLong(0).toInt())
    }

    override fun toString(): String {
        return if (peerCid != null) {
            "[CID:${cid?.toHex()}, peerCID:${peerCid?.toHex()}, cipher-suite:${getCipherSuite()}]"
        } else {
            "[cipher-suite:${getCipherSuite()}]"
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
