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

package benchmark

import ch.qos.logback.classic.Level
import ch.qos.logback.classic.Logger
import org.opencoap.ssl.CertificateAuth
import org.opencoap.ssl.HelloVerifyRequired
import org.opencoap.ssl.RandomCidSupplier
import org.opencoap.ssl.SslConfig
import org.opencoap.ssl.SslSession
import org.opencoap.ssl.transport.asByteBuffer
import org.opencoap.ssl.util.Certs
import org.opencoap.ssl.util.StoredSessionPair
import org.opencoap.ssl.util.localAddress
import org.openjdk.jmh.annotations.Benchmark
import org.openjdk.jmh.annotations.Fork
import org.openjdk.jmh.annotations.Measurement
import org.openjdk.jmh.annotations.Scope
import org.openjdk.jmh.annotations.Setup
import org.openjdk.jmh.annotations.State
import org.openjdk.jmh.annotations.TearDown
import org.openjdk.jmh.annotations.Threads
import org.openjdk.jmh.annotations.Warmup
import org.openjdk.jmh.infra.Blackhole
import org.slf4j.LoggerFactory
import java.nio.ByteBuffer
import java.nio.ByteOrder
import kotlin.random.Random

@State(Scope.Benchmark)
@Fork(value = 1, jvmArgsPrepend = ["-Xms128m", "-Xmx128m"])
@Threads(1)
@Warmup(iterations = 1, time = 5)
@Measurement(iterations = 1, time = 20)
open class SslContextBenchmark {

    val serverConf = SslConfig.server(CertificateAuth(Certs.serverChain, Certs.server.privateKey), reqAuthentication = false, cidSupplier = RandomCidSupplier(16), cipherSuites = listOf("TLS-ECDHE-ECDSA-WITH-AES-128-GCM-SHA256"))
    val clientConf = SslConfig.client(CertificateAuth.trusted(Certs.root.asX509()), cipherSuites = listOf("TLS-ECDHE-ECDSA-WITH-AES-128-GCM-SHA256"))
    lateinit var serverSession: SslSession
    lateinit var clientSession: SslSession
    lateinit var smallMessage: ByteBuffer
    lateinit var largeMessage: ByteBuffer
    lateinit var largeMessageDirectBuf: ByteBuffer
    val byteBufferDirect: ByteBuffer = ByteBuffer.allocateDirect(1400)

    @Setup
    fun setUp() {
        (LoggerFactory.getLogger(Logger.ROOT_LOGGER_NAME) as Logger).level = Level.WARN
        (LoggerFactory.getLogger("org.opencoap.ssl") as Logger).level = Level.WARN

        smallMessage = Random.nextBytes(64).asByteBuffer()
        largeMessage = Random.nextBytes(1280).asByteBuffer()
        largeMessageDirectBuf = ByteBuffer.allocateDirect(1280).order(ByteOrder.nativeOrder())
        largeMessageDirectBuf.put(Random.nextBytes(1280))
        largeMessageDirectBuf.flip()

        clientSession = clientConf.loadSession(byteArrayOf(), StoredSessionPair.cliSession, localAddress(2_5684))
        serverSession = serverConf.loadSession(byteArrayOf(), StoredSessionPair.srvSession, localAddress(1_5684))
    }

    @TearDown
    fun tearDown() {
        clientSession.close()
        serverSession.close()
        serverConf.close()
        clientConf.close()
    }

    @Benchmark
    fun encrypt_64b(bh: Blackhole) {
        bh.consume(serverSession.encrypt(smallMessage))
    }

    @Benchmark
    fun encrypt_1kb(bh: Blackhole) {
        val encrypted = serverSession.encrypt(largeMessage)
        bh.consume(encrypted)
    }

    @Benchmark
    fun encrypt_1kb_direct_memory(bh: Blackhole) {
        val encryptedMsg = serverSession.encrypt(largeMessageDirectBuf)
        bh.consume(encryptedMsg)
    }

    @Benchmark
    fun encrypt_and_decrypt_1kb(bh: Blackhole) {
        val encryptedMsg: ByteBuffer = clientSession.encrypt(largeMessage)
        val plainMsg = serverSession.decrypt(encryptedMsg, noSend)

        bh.consume(encryptedMsg)
        bh.consume(plainMsg)
    }

    @Benchmark
    fun encrypt_and_decrypt_1kb_direct_memory(bh: Blackhole) {
        byteBufferDirect.clear()
        val encryptedMsg: ByteBuffer = clientSession.encrypt(largeMessageDirectBuf)
        serverSession.decrypt(encryptedMsg, byteBufferDirect, noSend)

        bh.consume(encryptedMsg)
        bh.consume(byteBufferDirect)
    }

    private lateinit var sendingBuffer: ByteBuffer
    private val send: (ByteBuffer) -> Unit = { sendingBuffer = it }

    @Benchmark
    fun handshake_cert_ecdhe_ecdsa_with_aes_128_gcm(bh: Blackhole) {
        var srvHandshake = serverConf.newContext(localAddress(1_5684))
        val cliHandshake = clientConf.newContext(localAddress(2_5684))

        cliHandshake.step(send)
        try {
            srvHandshake.step(sendingBuffer) { cliHandshake.step(it, send) }
        } catch (ex: HelloVerifyRequired) {
            srvHandshake.close()
            srvHandshake = serverConf.newContext(localAddress(1_5684))
        }
        srvHandshake.step(sendingBuffer) { cliHandshake.step(it, send) }

        val sslSession = srvHandshake.step(sendingBuffer) { cliHandshake.step(it, send) } as SslSession
        sslSession.close()
        cliHandshake.close()

        bh.consume(sslSession)
    }

    @Benchmark
    fun create_and_close_ssl_context(bh: Blackhole) {
        val srvHandshake = serverConf.newContext(localAddress(1_5684))
        srvHandshake.close()

        bh.consume(srvHandshake)
    }

    @Benchmark
    fun load_and_save_ssl_session(bh: Blackhole) {
        val session = serverConf.loadSession(byteArrayOf(), StoredSessionPair.srvSession, localAddress(1_5684))
        val sessionData = session.saveAndClose()

        bh.consume(sessionData)
    }

    private val noSend: (ByteBuffer) -> Unit = { throw IllegalStateException() }
}
