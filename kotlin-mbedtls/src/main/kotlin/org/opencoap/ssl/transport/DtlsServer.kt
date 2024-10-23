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
import java.nio.ByteOrder
import java.time.Duration
import java.time.Instant
import java.util.concurrent.CompletableFuture
import java.util.concurrent.Future
import java.util.concurrent.ScheduledExecutorService

class DtlsServer(
    private val transport: TransportOutbound<ByteBufferPacket>,
    private val sslConfig: SslConfig,
    private val expireAfter: Duration = Duration.ofSeconds(60),
    private val storeSession: (cid: ByteArray, session: SessionWithContext) -> Unit,
    private val lifecycleCallbacks: DtlsSessionLifecycleCallbacks = object : DtlsSessionLifecycleCallbacks {},
    private val executor: ScheduledExecutorService,
    private val cidRequired: Boolean = false
) {
    companion object {
        private val EMPTY_BUFFER = ByteBuffer.allocate(0)
        private val NO_SCHEDULE_TASK: Future<*> = CompletableFuture.completedFuture(null)
    }

    private val logger = LoggerFactory.getLogger(javaClass)

    // note: non thread save, must be used only from same thread
    private val sessions = mutableMapOf<InetSocketAddress, DtlsState>()
    private val cidSize = sslConfig.cidSupplier?.next()?.size ?: 0
    val numberOfSessions get() = sessions.size

    fun handleReceived(adr: InetSocketAddress, buf: ByteBuffer): ReceiveResult {
        val cid by lazy { SslContext.peekCID(cidSize, buf) }
        val isValidHandshake by lazy { isValidHandshakeRequest(buf) }
        val dtlsState = sessions[adr]

        return when {
            dtlsState is DtlsHandshake -> dtlsState.step(buf)
            dtlsState is DtlsSession -> dtlsState.decrypt(buf)

            // no session, but dtls packet contains CID
            cid != null -> {
                if (sslConfig.cidSupplier?.isValidCid(cid!!) == false) {
                    logger.warn("[{}] [CID:{}] Invalid CID", adr, cid!!.toHex())
                    reportMessageDrop(adr)
                    ReceiveResult.Handled
                } else {
                    ReceiveResult.CidSessionMissing(cid!!)
                }
            }

            // start new handshake if datagram is valid
            isValidHandshake -> {
                val dtlsHandshake = DtlsHandshake(sslConfig.newContext(adr), adr)
                sessions[adr] = dtlsHandshake
                dtlsHandshake.step(buf)
            }

            // drop silently
            else -> {
                logger.warn("[{}] Invalid DTLS session handshake.", adr)
                reportMessageDrop(adr)
                ReceiveResult.Handled
            }
        }
    }

    fun encrypt(plainPacket: ByteBuffer, peerAddress: InetSocketAddress): ByteBuffer? {
        return (sessions[peerAddress] as? DtlsSession)?.encrypt(plainPacket)
    }

    private fun updateSessionAuthenticationContext(adr: InetSocketAddress, authCtxUpdate: Map<String, String?>): Boolean {
        if (authCtxUpdate.isEmpty()) return true

        return when (val s = sessions[adr] as? DtlsSession) {
            null -> false

            else -> {
                authCtxUpdate.forEach { (key, value) ->
                    if (value != null) {
                        s.authenticationContext += (key to value)
                    } else {
                        s.authenticationContext -= key
                    }
                }
                true
            }
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

    private fun closeSession(addr: InetSocketAddress) {
        sessions.remove(addr)?.apply {
            storeAndClose()
            logger.info(
                "[{}] [CID:{}] DTLS session was stored",
                peerAddress,
                (this as? DtlsSession)?.sessionContext?.cid?.toHex()
                    ?: "na"
            )
        }
    }

    fun handleOutboundDtlsSessionContext(adr: InetSocketAddress, ctx: DtlsSessionContext, writeFuture: CompletableFuture<Boolean>) {
        if (ctx.sessionSuspensionHint) {
            writeFuture.thenAccept {
                closeSession(adr)
            }
        }
        updateSessionAuthenticationContext(adr, ctx.authenticationContext)
    }

    fun loadSession(sessBuf: SessionWithContext?, adr: InetSocketAddress, cid: ByteArray, dtlsPacket: ByteBuffer): Boolean {
        return try {
            if (sessBuf == null) {
                logger.warn("[{}] [CID:{}] DTLS session not found", adr, cid.toHex())
                reportMessageDrop(adr)
                return false
            }

            val sslSession = sslConfig.loadSession(cid, sessBuf.sessionBlob, adr)
            dtlsPacket.let {
                val verificationResult = sslSession.checkRecord(it)
                if (verificationResult is SslSession.VerificationResult.Invalid) {
                    logger.warn("[{}] [CID:{}] Record verification failed: {}", adr, cid.toHex(), verificationResult.message)
                    reportMessageDrop(adr)
                    return false
                }
            }
            sessions[adr] = DtlsSession(sslSession, adr, sessBuf.authenticationContext, sessBuf.sessionStartTimestamp)
            true
        } catch (ex: Exception) {
            logger.error("[{}] [CID:{}] DTLS failed to load session: {}", adr, cid.toHex(), ex.message)
            reportMessageDrop(adr)
            false
        }
    }

    private fun reportMessageDrop(adr: InetSocketAddress) {
        lifecycleCallbacks.messageDropped(adr)
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
        protected lateinit var scheduledTask: Future<*>

        abstract fun storeAndClose0()
        fun storeAndClose() {
            scheduledTask.cancel(false)
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
            scheduledTask = NO_SCHEDULE_TASK
            reportHandshakeStarted()
        }

        private fun retryStep() = step(EMPTY_BUFFER)

        fun step(encPacket: ByteBuffer): ReceiveResult {
            scheduledTask.cancel(false)

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
                        sessions[peerAddress] = DtlsSession(newCtx, peerAddress)
                        reportHandshakeFinished(DtlsSessionLifecycleCallbacks.Reason.SUCCEEDED)
                    }
                }
            } catch (ex: HelloVerifyRequired) {
                closeAndRemove()
                reportHandshakeFinished(DtlsSessionLifecycleCallbacks.Reason.FAILED, ex)
            } catch (ex: Exception) {
                when (ex) {
                    is SslException ->
                        logger.warn("[{}] DTLS failed: {}", peerAddress, ex.message)

                    else ->
                        logger.error(ex.toString(), ex)
                }
                closeAndRemove()
                reportHandshakeFinished(DtlsSessionLifecycleCallbacks.Reason.FAILED, ex)
                reportMessageDrop(peerAddress)
            }
            return ReceiveResult.Handled
        }

        fun timeout() {
            closeAndRemove()
            logger.warn("[{}] DTLS handshake expired", peerAddress)
            reportHandshakeFinished(DtlsSessionLifecycleCallbacks.Reason.EXPIRED)
        }

        override fun storeAndClose0() = close()

        override fun close() = ctx.close()

        private fun reportHandshakeStarted() {
            lifecycleCallbacks.handshakeStarted(peerAddress)
        }

        private fun reportHandshakeFinished(reason: DtlsSessionLifecycleCallbacks.Reason, err: Throwable? = null) {
            lifecycleCallbacks.handshakeFinished(peerAddress, ctx.startTimestamp, ctx.finishTimestamp, reason, err)
        }
    }

    private inner class DtlsSession(
        private val ctx: SslSession,
        peerAddress: InetSocketAddress,
        var authenticationContext: AuthenticationContext = emptyMap(),
        private val sessionStartTimestamp: Instant = Instant.now()
    ) : DtlsState(peerAddress) {

        val sessionContext: DtlsSessionContext
            get() = DtlsSessionContext(
                peerCertificateSubject = ctx.peerCertificateSubject,
                authenticationContext = authenticationContext,
                cid = if (ctx.ownCid?.isEmpty() != true) ctx.ownCid else ctx.peerCid,
                sessionStartTimestamp = sessionStartTimestamp
            )

        init {
            scheduledTask = executor.schedule(::timeout, expireAfter)
            reportSessionStarted()
        }

        override fun storeAndClose0() {
            if (ctx.ownCid != null) {
                try {
                    val session = SessionWithContext(
                        sessionBlob = ctx.saveAndClose(),
                        authenticationContext = authenticationContext,
                        sessionStartTimestamp = sessionStartTimestamp
                    )
                    storeSession(ctx.ownCid, session)
                    reportSessionFinished(DtlsSessionLifecycleCallbacks.Reason.STORED)
                } catch (ex: Exception) {
                    logger.error("[{}] [CID:{}] DTLS failed to store session: {}", peerAddress, ownCidHex, ex.message)
                    reportSessionFinished(DtlsSessionLifecycleCallbacks.Reason.FAILED, ex)
                }
            } else {
                close()
                reportSessionFinished(DtlsSessionLifecycleCallbacks.Reason.CLOSED)
            }
        }

        override fun close() = ctx.close()

        fun decrypt(encPacket: ByteBuffer): ReceiveResult {
            scheduledTask.cancel(false)
            try {
                val plainBuf = ctx.decrypt(encPacket, ::send)
                scheduledTask = executor.schedule(::timeout, expireAfter)
                return if (plainBuf.isNotEmpty()) {
                    ReceiveResult.Decrypted(Packet(plainBuf, peerAddress, sessionContext))
                } else {
                    ReceiveResult.Handled
                }
            } catch (ex: CloseNotifyException) {
                logger.info("[{}] [CID:{}] DTLS received close notify", peerAddress, ownCidHex)
                reportSessionFinished(DtlsSessionLifecycleCallbacks.Reason.CLOSED)
            } catch (ex: SslException) {
                logger.warn("[{}] [CID:{}] DTLS failed: {}", peerAddress, ownCidHex, ex.message)
                reportSessionFinished(DtlsSessionLifecycleCallbacks.Reason.FAILED, ex)
                reportMessageDrop(peerAddress)
            }

            closeAndRemove()
            return ReceiveResult.DecryptFailed
        }

        fun encrypt(plainPacket: ByteBuffer): ByteBuffer {
            try {
                return ctx.encrypt(plainPacket)
            } catch (ex: SslException) {
                closeAndRemove()
                logger.warn("[{}] [CID:{}] DTLS failed: {}", peerAddress, ownCidHex, ex.message)
                reportSessionFinished(DtlsSessionLifecycleCallbacks.Reason.FAILED, ex)
                throw ex
            }
        }

        fun timeout() {
            sessions.remove(peerAddress, this)
            storeAndClose()
            logger.info("[{}] [CID:{}] DTLS session stored after idle", peerAddress, ownCidHex)
            reportSessionFinished(DtlsSessionLifecycleCallbacks.Reason.EXPIRED)
        }

        private val ownCidHex: String get() = ctx.ownCid?.toHex() ?: "na"

        private fun reportSessionStarted() {
            lifecycleCallbacks.sessionStarted(peerAddress, ctx.cipherSuite, ctx.reloaded)
        }

        private fun reportSessionFinished(reason: DtlsSessionLifecycleCallbacks.Reason, err: Throwable? = null) {
            lifecycleCallbacks.sessionFinished(peerAddress, reason, err)
        }
    }

    private fun isValidHandshakeRequest(buf: ByteBuffer): Boolean {
        val workingBuf = buf.slice().order(ByteOrder.BIG_ENDIAN)

        // Check if the header is correct:
        // - Content Type is Handshake(0x16),
        // - Major version is 1 (0xFE),
        // - Minor version is any,
        // - Epoch is 0
        val header = (workingBuf.getLong(0) or 0x0000FF0000000000) ushr 24
        if (header != 0x16FEFF0000L) {
            logger.debug("Bad DTLS header")
            return false
        }

        // Check if it is a ClientHello handshake
        val handshakeType = workingBuf.get(13).toInt()
        if (handshakeType != 1) {
            logger.debug("Bad handshake type")
            return false
        }

        // Check if CID is supported by the client in case if CID support is mandatory
        if (cidRequired && !supportsCid(workingBuf)) {
            logger.debug("No CID support")
            return false
        }

        return true
    }

    private fun supportsCid(buf: ByteBuffer): Boolean {
        val workingBuffer = buf.slice().order(ByteOrder.BIG_ENDIAN)

        // Go to the start of extensions
        workingBuffer
            // Skip DTLSHeader(13) + HandshakeHeader(12) + SessionIDLengthOffset(34)
            .seek(59)
            // Skip variable-length Session ID
            .readByteAndSeek()
            // Skip variable-length Cookie
            .readByteAndSeek()
            // Skip variable-length CipherSuites
            .readShortAndSeek()
            // Skip variable-length CompressionMethods
            .readByteAndSeek()
            // Limit buffer to the length of the Extensions block
            .readShortAndLimit()

        // Search for CID extension
        while (workingBuffer.remaining() >= 4) {
            val type = workingBuffer.getShort()
            if (type == 0x36.toShort()) {
                return true
            }

            // Skip to the next extension
            workingBuffer.readShortAndSeek()
        }

        return false
    }
}

fun ByteBuffer.seek(offset: Int): ByteBuffer = this.position(this.position() + offset) as ByteBuffer
fun ByteBuffer.readShortAndSeek(): ByteBuffer = this.getShort().toUShort().let { this.seek(it.toInt()) }
fun ByteBuffer.readByteAndSeek(): ByteBuffer = this.get().toUByte().let { this.seek(it.toInt()) }
fun ByteBuffer.readShortAndLimit(): ByteBuffer = this.getShort().toUShort().let { this.limit(this.position() + it.toInt()) } as ByteBuffer
