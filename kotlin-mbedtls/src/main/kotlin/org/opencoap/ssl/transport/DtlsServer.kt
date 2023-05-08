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

package org.opencoap.ssl.transport

import org.opencoap.ssl.CloseNotifyException
import org.opencoap.ssl.HelloVerifyRequired
import org.opencoap.ssl.SslConfig
import org.opencoap.ssl.SslContext
import org.opencoap.ssl.SslException
import org.opencoap.ssl.SslHandshakeContext
import org.opencoap.ssl.SslSession
import org.slf4j.LoggerFactory
import java.net.InetSocketAddress
import java.nio.ByteBuffer
import java.time.Duration
import java.util.concurrent.ScheduledExecutorService
import java.util.concurrent.ScheduledFuture

class DtlsServer(
    private val transport: TransportOutbound<ByteBufferPacket>,
    private val sslConfig: SslConfig,
    private val expireAfter: Duration = Duration.ofSeconds(60),
    private val storeSession: (cid: ByteArray, session: SessionWithContext) -> Unit,
    private val lifecycleCallbacks: DtlsSessionLifecycleCallbacks = object : DtlsSessionLifecycleCallbacks {},
    private val executor: ScheduledExecutorService
) {
    companion object {
        private val EMPTY_BUFFER = ByteBuffer.allocate(0)
    }

    private val logger = LoggerFactory.getLogger(javaClass)

    // note: non thread save, must be used only from same thread
    private val sessions = mutableMapOf<InetSocketAddress, DtlsState>()
    private val cidSize = sslConfig.cidSupplier.next().size
    val numberOfSessions get() = sessions.size

    fun handleReceived(adr: InetSocketAddress, buf: ByteBuffer): ReceiveResult {
        val cid by lazy { SslContext.peekCID(cidSize, buf) }
        val dtlsState = sessions[adr]

        return when {
            dtlsState is DtlsHandshake -> dtlsState.step(buf)
            dtlsState is DtlsSession -> dtlsState.decrypt(buf)

            // no session, but dtls packet contains CID
            cid != null -> ReceiveResult.CidSessionMissing(cid!!)

            // new handshake
            else -> {
                val dtlsHandshake = DtlsHandshake(sslConfig.newContext(adr), adr)
                sessions[adr] = dtlsHandshake
                dtlsHandshake.step(buf)
                ReceiveResult.Handled
            }
        }
    }

    fun encrypt(plainPacket: ByteBuffer, peerAddress: InetSocketAddress): ByteBuffer? {
        return (sessions[peerAddress] as? DtlsSession)?.encrypt(plainPacket)
    }

    fun putSessionAuthenticationContext(adr: InetSocketAddress, key: String, value: String?): Boolean {
        return when (val s = sessions[adr]) {
            is DtlsSession -> {
                if (value != null) {
                    s.authenticationContext += (key to value)
                } else {
                    s.authenticationContext -= key
                }
                true
            }

            else -> false
        }
    }

    fun closeSessions() {
        val iterator = sessions.iterator()
        while (iterator.hasNext()) {
            val dtlsState = iterator.next().value
            iterator.remove()
            dtlsState.storeAndClose()
        }
    }

    fun loadSession(sessBuf: SessionWithContext?, adr: InetSocketAddress, cid: ByteArray): Boolean {
        return try {
            if (sessBuf == null) {
                logger.warn("[{}] [CID:{}] DTLS session not found", adr, cid.toHex())
                false
            } else {
                sessions[adr] = DtlsSession(sslConfig.loadSession(cid, sessBuf.sessionBlob, adr), adr, sessBuf.authenticationContext)
                true
            }
        } catch (ex: SslException) {
            logger.warn("[{}] [CID:{}] Failed to load session: {}", adr, cid.toHex(), ex.message)
            false
        }
    }

    private fun DtlsState.closeAndRemove() {
        sessions.remove(this.peerAddress, this)
        this.close()
    }

    sealed interface ReceiveResult {
        object Handled : ReceiveResult
        object DecryptFailed : ReceiveResult
        class Decrypted(val packet: Packet<ByteBuffer>) : ReceiveResult
        class CidSessionMissing(val cid: ByteArray) : ReceiveResult
    }

    private abstract inner class DtlsState(val peerAddress: InetSocketAddress) {
        protected var scheduledTask: ScheduledFuture<*>? = null

        abstract fun storeAndClose0()
        fun storeAndClose() {
            scheduledTask?.cancel(false)
            storeAndClose0()
        }

        fun send(buf: ByteBuffer) {
            transport.send(Packet(buf, peerAddress))
        }

        abstract fun close()
    }

    private inner class DtlsHandshake(
        private val ctx: SslHandshakeContext,
        peerAddress: InetSocketAddress,
    ) : DtlsState(peerAddress) {

        init {
            reportHandshakeStarted()
        }

        private fun retryStep() = step(EMPTY_BUFFER)

        fun step(encPacket: ByteBuffer): ReceiveResult {
            scheduledTask?.cancel(false)

            try {
                when (val newCtx = ctx.step(encPacket, ::send)) {
                    is SslHandshakeContext -> {
                        scheduledTask = if (!newCtx.readTimeout.isZero) {
                            executor.schedule(::retryStep, newCtx.readTimeout)
                        } else {
                            executor.schedule(::timeout, expireAfter)
                        }
                    }

                    is SslSession -> {
                        reportHandshakeFinished(DtlsSessionLifecycleCallbacks.Reason.SUCCEEDED)
                        sessions[peerAddress] = DtlsSession(newCtx, peerAddress)
                    }
                }
            } catch (ex: Exception) {
                when (ex) {
                    is HelloVerifyRequired -> {}
                    is SslException ->
                        logger.warn("[{}] DTLS failed: {}", peerAddress, ex.message)

                    else ->
                        logger.error(ex.toString(), ex)
                }
                reportHandshakeFinished(DtlsSessionLifecycleCallbacks.Reason.FAILED, ex)
                closeAndRemove()
            }
            return ReceiveResult.Handled
        }

        fun timeout() {
            reportHandshakeFinished(DtlsSessionLifecycleCallbacks.Reason.EXPIRED)
            closeAndRemove()
            logger.warn("[{}] DTLS handshake expired", peerAddress)
        }

        override fun storeAndClose0() = close()

        override fun close() = ctx.close()

        private fun reportHandshakeStarted() {
            lifecycleCallbacks.handshakeStarted(peerAddress)
        }

        private fun reportHandshakeFinished(reason: DtlsSessionLifecycleCallbacks.Reason, err: Throwable? = null) {
            lifecycleCallbacks.handshakeFinished(peerAddress, ctx.startTimestamp, reason, err)
        }
    }

    private inner class DtlsSession(
        private val ctx: SslSession,
        peerAddress: InetSocketAddress,
        var authenticationContext: AuthenticationContext = emptyMap()
    ) : DtlsState(peerAddress) {

        val sessionContext: DtlsSessionContext
            get() = DtlsSessionContext(
                peerCertificateSubject = ctx.peerCertificateSubject,
                authenticationContext = authenticationContext
            )

        init {
            reportSessionStarted()
        }

        override fun storeAndClose0() {
            if (ctx.ownCid != null) {
                try {
                    val session = SessionWithContext(
                        sessionBlob = ctx.saveAndClose(),
                        authenticationContext = authenticationContext
                    )
                    storeSession(ctx.ownCid, session)
                } catch (ex: SslException) {
                    logger.warn("[{}] DTLS failed to store session: {}, CID:{}", peerAddress, ex.message, ctx.ownCid.toHex())
                }
            } else {
                close()
            }
        }

        override fun close() = ctx.close()

        fun decrypt(encPacket: ByteBuffer): ReceiveResult {
            scheduledTask?.cancel(false)
            try {
                val plainBuf = ctx.decrypt(encPacket, ::send)
                scheduledTask = executor.schedule(::timeout, expireAfter)
                return if (plainBuf.isNotEmpty()) {
                    ReceiveResult.Decrypted(Packet(plainBuf, peerAddress, sessionContext))
                } else {
                    ReceiveResult.Handled
                }
            } catch (ex: CloseNotifyException) {
                logger.info("[{}] DTLS received close notify", peerAddress)
                reportSessionFinished(DtlsSessionLifecycleCallbacks.Reason.CLOSED)
            } catch (ex: SslException) {
                logger.warn("[{}] DTLS failed: {}", peerAddress, ex.message)
                reportSessionFinished(DtlsSessionLifecycleCallbacks.Reason.FAILED, ex)
            }

            closeAndRemove()
            return ReceiveResult.DecryptFailed
        }

        fun encrypt(plainPacket: ByteBuffer): ByteBuffer {
            try {
                return ctx.encrypt(plainPacket)
            } catch (ex: SslException) {
                logger.warn("[{}] DTLS failed: {}", peerAddress, ex.message)
                reportSessionFinished(DtlsSessionLifecycleCallbacks.Reason.FAILED, ex)
                closeAndRemove()
                throw ex
            }
        }

        fun timeout() {
            lifecycleCallbacks.sessionFinished(peerAddress, DtlsSessionLifecycleCallbacks.Reason.EXPIRED)
            sessions.remove(peerAddress, this)
            logger.info("[{}] DTLS connection expired", peerAddress)
            storeAndClose()
        }

        private fun reportSessionStarted() {
            lifecycleCallbacks.sessionStarted(peerAddress, ctx.cipherSuite, ctx.reloaded)
        }

        private fun reportSessionFinished(reason: DtlsSessionLifecycleCallbacks.Reason, err: Throwable? = null) {
            lifecycleCallbacks.sessionFinished(peerAddress, reason, err)
        }
    }
}
