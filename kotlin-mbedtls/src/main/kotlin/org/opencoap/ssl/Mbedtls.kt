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

import java.net.InetSocketAddress
import java.nio.ByteBuffer

/**
 * Opaque handle to a native DTLS configuration owned by an [Mbedtls] engine.
 *
 * Core code never inspects the concrete type; engines back it with whatever native
 * representation they need (e.g. a JNA `Memory` block).
 */
interface NativeConf

/**
 * Opaque handle to a native DTLS context (handshake or established session) owned by an [Mbedtls] engine.
 */
interface NativeContext

/**
 * Engine SPI bridging the native mbedtls library.
 *
 * The boundary follows the design split: the **core** owns the stateful, bug-prone orchestration
 * (handshake step loop, encrypt/decrypt, save/close, retransmission/timeout, the callback dance via [Bio]);
 * the **engine** owns mechanical native work driven by data.
 */
interface Mbedtls {
    /** Build a native configuration from a pure-data [ConfigSpec]. */
    fun buildConfig(spec: ConfigSpec): NativeConf

    /** Free a native configuration previously returned by [buildConfig]. */
    fun freeConfig(conf: NativeConf)

    /** Create a fresh handshake context wired to [bio] for I/O. */
    fun newContext(conf: NativeConf, ownCid: ByteArray?, mtu: Int, peerAddress: InetSocketAddress, bio: Bio): NativeContext

    /** Restore a previously saved session context wired to [bio] for I/O. */
    fun loadContext(conf: NativeConf, session: ByteArray, bio: Bio): NativeContext

    /** Drive one handshake step; returns the raw mbedtls return code. */
    fun handshake(ctx: NativeContext): Int

    /** Read decrypted application data into [plainBuffer]; returns the raw mbedtls return code. */
    fun read(ctx: NativeContext, plainBuffer: ByteBuffer): Int

    /** Encrypt and write application [data]; returns the raw mbedtls return code. */
    fun write(ctx: NativeContext, data: ByteBuffer): Int

    /** Check a record without consuming it; returns the raw mbedtls return code. */
    fun checkRecord(ctx: NativeContext, encBuffer: ByteBuffer): Int

    /** Serialize the session context for later restoration. */
    fun contextSave(ctx: NativeContext): ByteArray

    /** Emit a close-notify alert; returns the raw mbedtls return code. */
    fun closeNotify(ctx: NativeContext): Int

    /** Free a native context previously returned by [newContext] / [loadContext]. */
    fun free(ctx: NativeContext)

    /** Read the negotiated peer CID, or `null` if CID is not in use. */
    fun getPeerCid(ctx: NativeContext): ByteArray?

    /** Read the peer certificate in DER form, or `null` if none was presented. */
    fun getPeerCertDer(ctx: NativeContext): ByteArray?

    /** Read the negotiated cipher-suite name. */
    fun getCiphersuite(ctx: NativeContext): String

    /** Translate an mbedtls error code into a human readable message. */
    fun strError(error: Int): String

    companion object {
        // ----- mbedtls return codes needed by the core orchestration -----
        const val MBEDTLS_ERR_SSL_TIMEOUT = -0x6800
        const val MBEDTLS_ERR_SSL_WANT_READ = -0x6900
        const val MBEDTLS_ERR_SSL_WANT_WRITE = -0x6880
        const val MBEDTLS_ERR_SSL_HELLO_VERIFY_REQUIRED = -0x6A80
        const val MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY = -0x7880
        const val MBEDTLS_ERR_SSL_UNEXPECTED_RECORD = -0x6700

        // ----- net_sockets.h -----
        const val MBEDTLS_ERR_NET_RECV_FAILED = -0x004C
        const val MBEDTLS_ERR_NET_SEND_FAILED = -0x004E
    }
}

/**
 * Pure-data description of a DTLS configuration. The engine interprets this into native calls in
 * [Mbedtls.buildConfig]; it contains no native types.
 */
data class ConfigSpec(
    val isServer: Boolean,
    val auth: AuthConfig,
    val cipherSuites: List<String>,
    val requiredAuthMode: Boolean,
    /** CID length to advertise, or 0 when CID is disabled. */
    val cidLength: Int,
    val retransmitMinMillis: Int,
    val retransmitMaxMillis: Int,
)
