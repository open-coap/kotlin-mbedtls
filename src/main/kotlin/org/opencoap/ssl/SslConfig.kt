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
import org.opencoap.ssl.MbedtlsApi.mbedtls_ctr_drbg_random
import org.opencoap.ssl.MbedtlsApi.mbedtls_ctr_drbg_seed
import org.opencoap.ssl.MbedtlsApi.mbedtls_ssl_conf_authmode
import org.opencoap.ssl.MbedtlsApi.mbedtls_ssl_conf_cid
import org.opencoap.ssl.MbedtlsApi.mbedtls_ssl_conf_ciphersuites
import org.opencoap.ssl.MbedtlsApi.mbedtls_ssl_conf_dbg
import org.opencoap.ssl.MbedtlsApi.mbedtls_ssl_conf_dtls_cookies
import org.opencoap.ssl.MbedtlsApi.mbedtls_ssl_conf_min_version
import org.opencoap.ssl.MbedtlsApi.mbedtls_ssl_conf_psk
import org.opencoap.ssl.MbedtlsApi.mbedtls_ssl_conf_rng
import org.opencoap.ssl.MbedtlsApi.mbedtls_ssl_config_defaults
import org.opencoap.ssl.MbedtlsApi.mbedtls_ssl_context_load
import org.opencoap.ssl.MbedtlsApi.mbedtls_ssl_get_ciphersuite_id
import org.opencoap.ssl.MbedtlsApi.mbedtls_ssl_set_bio
import org.opencoap.ssl.MbedtlsApi.mbedtls_ssl_set_cid
import org.opencoap.ssl.MbedtlsApi.mbedtls_ssl_set_timer_cb
import org.opencoap.ssl.MbedtlsApi.mbedtls_ssl_setup
import org.opencoap.ssl.MbedtlsApi.verify
import org.slf4j.LoggerFactory

class SslConfig(
    private val conf: Memory,
    private val cid: ByteArray?,
    private val allocated: Array<Memory> //keep in memory to prevent GC
) {

    fun newContext(trans: IOTransport): SslHandshakeContext {
        val sslContext = Memory(MbedtlsSizeOf.mbedtls_ssl_context).apply(MbedtlsApi::mbedtls_ssl_init)

        mbedtls_ssl_setup(sslContext, conf).verify()
        mbedtls_ssl_set_timer_cb(sslContext, Pointer.NULL, NoOpsSetDelayCallback, NoOpsGetDelayCallback)

        val sendCallback = SendCallback(trans)
        val receiveCallback = ReceiveCallback()

        if (cid != null) {
            mbedtls_ssl_set_cid(sslContext, 1, cid, cid.size).verify()
        }

        mbedtls_ssl_set_bio(sslContext, Pointer.NULL, sendCallback, null, receiveCallback)

        return SslHandshakeContext(this, sslContext, trans, receiveCallback, sendCallback)
    }

    fun newContext(trans: IOTransport, session: ByteArray): SslSession {
        val sslContext = Memory(MbedtlsSizeOf.mbedtls_ssl_context).apply(MbedtlsApi::mbedtls_ssl_init)

        mbedtls_ssl_setup(sslContext, conf).verify()
        val buffer = Memory(session.size.toLong())
        buffer.write(0, session, 0, session.size)
        mbedtls_ssl_context_load(sslContext, buffer, buffer.size().toInt()).verify()

        val sendCallback = SendCallback(trans)
        val receiveCallback = ReceiveCallback()
        mbedtls_ssl_set_bio(sslContext, Pointer.NULL, sendCallback, null, receiveCallback)

        return SslSession(this, sslContext, trans, receiveCallback, sendCallback)
    }

    companion object {

        @JvmStatic
        @JvmOverloads
        fun client(pskId: ByteArray, pskSecret: ByteArray, cipherSuites: List<String> = emptyList(), cid: ByteArray? = ByteArray(0)): SslConfig {
            return create(false, pskId, pskSecret, cipherSuites, cid);
        }

        @JvmStatic
        @JvmOverloads
        fun server(pskId: ByteArray, pskSecret: ByteArray, cipherSuites: List<String> = emptyList(), cid: ByteArray? = null): SslConfig {
            return create(true, pskId, pskSecret, cipherSuites, cid);
        }

        private fun create(isServer: Boolean = false, pskId: ByteArray, pskSecret: ByteArray, cipherSuites: List<String>, cid: ByteArray?): SslConfig {
            val sslConfig = initMemory(MbedtlsSizeOf.mbedtls_ssl_config, MbedtlsApi::mbedtls_ssl_config_init)
            val entropy = initMemory(MbedtlsSizeOf.mbedtls_entropy_context, MbedtlsApi::mbedtls_entropy_init)
            val ctrDrbg = initMemory(MbedtlsSizeOf.mbedtls_ctr_drbg_context, MbedtlsApi::mbedtls_ctr_drbg_init)

            val endpointType = if (isServer) MbedtlsApi.MBEDTLS_SSL_IS_SERVER else MbedtlsApi.MBEDTLS_SSL_IS_CLIENT
            mbedtls_ssl_config_defaults(sslConfig, endpointType, MbedtlsApi.MBEDTLS_SSL_TRANSPORT_DATAGRAM, MbedtlsApi.MBEDTLS_SSL_PRESET_DEFAULT).verify()
            mbedtls_ssl_conf_min_version(sslConfig, MbedtlsApi.MBEDTLS_SSL_MAJOR_VERSION_3, MbedtlsApi.MBEDTLS_SSL_MINOR_VERSION_3)

            mbedtls_ctr_drbg_seed(ctrDrbg, MbedtlsApi.mbedtls_entropy_func, entropy, Pointer.NULL, 0).verify()
            mbedtls_ssl_conf_rng(sslConfig, mbedtls_ctr_drbg_random, ctrDrbg);
            mbedtls_ssl_conf_dtls_cookies(sslConfig, null, null, null)

            // PSK
            mbedtls_ssl_conf_psk(sslConfig, pskSecret, pskSecret.size, pskId, pskId.size).verify()
            mbedtls_ssl_conf_authmode(sslConfig, MbedtlsApi.MBEDTLS_SSL_VERIFY_REQUIRED)
            if (cipherSuites.isNotEmpty()) {
                mbedtls_ssl_conf_ciphersuites(sslConfig, mapCipherSuites(cipherSuites)).verify()
            }

            if (cid != null) {
                mbedtls_ssl_conf_cid(sslConfig, cid.size, 0)
            }
            // Logging
            mbedtls_ssl_conf_dbg(sslConfig, LogCallback, Pointer.NULL)

            return SslConfig(sslConfig, cid, arrayOf(entropy, ctrDrbg))
        }


        private fun mapCipherSuites(cipherSuites: List<String>): Memory {
            val ids = cipherSuites.map(Companion::getCipherSuiteId).toIntArray()

            val cipherSuiteList = Memory(((ids.size + 1) * 4).toLong());
            cipherSuiteList.write(0, ids, 0, ids.size);
            cipherSuiteList.setInt(cipherSuiteList.size() - 4, 0);
            return cipherSuiteList;
        }

        private fun getCipherSuiteId(cipherSuite: String): Int {
            val id = mbedtls_ssl_get_ciphersuite_id(cipherSuite)
            if (id <= 0) throw SslException("Unknown cipher-suite: $cipherSuite")
            return id
        }

        private fun initMemory(size: Long, initFunc: (p: Pointer) -> Unit): Memory {
            return Memory(size).apply(initFunc)
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
