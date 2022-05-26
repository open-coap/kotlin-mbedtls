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
import org.opencoap.ssl.MbedtlsApi.mbedtls_ssl_context_save
import org.opencoap.ssl.MbedtlsApi.mbedtls_ssl_get_ciphersuite
import org.opencoap.ssl.MbedtlsApi.mbedtls_ssl_get_peer_cid
import org.opencoap.ssl.MbedtlsApi.mbedtls_ssl_handshake
import org.opencoap.ssl.MbedtlsApi.mbedtls_ssl_read
import org.opencoap.ssl.MbedtlsApi.mbedtls_ssl_write
import org.opencoap.ssl.MbedtlsApi.verify
import java.util.concurrent.CompletableFuture
import java.util.concurrent.CompletableFuture.completedFuture

sealed interface SslContext

class SslHandshakeContext(
    private val conf: SslConfig, // keep in memory to prevent GC
    private val sslContext: Memory,
    private val transport: IOTransport,
    private val recvCallback: ReceiveCallback,
    private val sendCallback: Callback, // keep in memory to prevent GC
) : SslContext {

    fun handshake(): CompletableFuture<SslSession> {
        val ret = mbedtls_ssl_handshake(sslContext)
        if (ret == MbedtlsApi.MBEDTLS_ERR_SSL_WANT_READ) {
            return continueHandshake()
        } else {
            throw SslException.from(ret)
        }
    }

    private fun continueHandshake(): CompletableFuture<SslSession> {
        return transport
            .receive()
            .thenCompose {
                recvCallback.localReadBuffer.set(it)
                val ret = mbedtls_ssl_handshake(sslContext)
                recvCallback.localReadBuffer.remove()

                when (ret) {
                    MbedtlsApi.MBEDTLS_ERR_SSL_WANT_READ -> continueHandshake()
                    0 -> completedFuture(SslSession(conf, sslContext, transport, recvCallback, sendCallback))
                    else -> throw SslException.from(ret)
                }
            }
    }
}

class SslSession(
    private val conf: SslConfig, // keep in memory to prevent GC
    private val sslContext: Memory,
    private val transport: IOTransport,
    private val recvCallback: ReceiveCallback,
    private val sendCallback: Callback, // keep in memory to prevent GC
) : SslContext {

    fun getPeerCid(): ByteArray? {
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

    fun send(data: ByteArray) {
        val buffer = Memory(data.size.toLong())
        buffer.write(0, data, 0, data.size)
        mbedtls_ssl_write(sslContext, buffer, data.size).verify()
    }

    fun read(): CompletableFuture<ByteArray> {
        return transport
            .receive()
            .thenApply {
                recvCallback.localReadBuffer.set(it)

                val buffer = Memory(it.remaining().toLong())
                val size = mbedtls_ssl_read(sslContext, buffer, buffer.size().toInt()).verify()
                recvCallback.localReadBuffer.remove()
                buffer.getByteArray(0, size)
            }
    }

    fun save(): ByteArray {
        val buffer = Memory(512)
        val outputLen = Memory(8)
        mbedtls_ssl_context_save(sslContext, buffer, buffer.size().toInt(), outputLen).verify()

        return buffer.getByteArray(0, outputLen.getLong(0).toInt())
    }
}
