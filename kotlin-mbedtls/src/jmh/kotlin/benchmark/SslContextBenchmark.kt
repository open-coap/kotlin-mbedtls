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
import org.opencoap.ssl.util.Certs
import org.opencoap.ssl.util.decodeHex
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
    lateinit var smallMessage: ByteArray
    lateinit var largeMessage: ByteArray

    // copied from DtlsTransmitterCertTest.`should successfully handshake with server only cert`
    val cliSession = "030300003700000f000001bc03000000006436877ac02b204cbe4b8ae08843b7c4438c9e4ec82c9fcdbc09a71cfe9cb78f68b3df8083dc0dbb7e8d9dee577c6abec96b25a82bf1a460d0a9ede05c0a4b4e10795d22dd8b2609e519e10ab90adf9e74ad2007bd5101000000000001513082014d3081f3a0030201020206018775012f65300a06082a8648ce3d040302302e3110300e06035504030c07726f6f742d6361310d300b060355040a0c0441636d65310b3009060355040613024649301e170d3233303431323130323730345a170d3233303431323131323730345a302d310f300d06035504030c06736572766572310d300b060355040a0c0441636d65310b30090603550406130246493059301306072a8648ce3d020106082a8648ce3d030107034200048f89e89ed6efae67b97ad1179cc385a47b775addb979baad390832ab3bcf973fc0ca39fa2668c08ee6c78773692e31311532a7e991dbd955e238e7453ccf8c97300a06082a8648ce3d0403020349003046022100fe808daf73d895daebe62aa5a9fea670bbd89a5f0f290b309f4d002b52db3764022100cc9261dd7a24bfc18726dbad8d902638822daac325cf71e5ec8151e4397f738f00000000000000006436877a29ba610553ec89ffc3865d5a6b16ad0af0ba094a3dda6e3e9878ff556436877a95153dbf344fbf78c42ddf5dad8eec94a85ea328b812e66a5b0594ec0010f935adc57425e1b214f8640d56e0c7330000000000000000000000000000000000000001000001000000000002000000".decodeHex()
    val srvSession = "030300003700000f0000006b03000000006436877ac02b204cbe4b8ae08843b7c4438c9e4ec82c9fcdbc09a71cfe9cb78f68b3df8083dc0dbb7e8d9dee577c6abec96b25a82bf1a460d0a9ede05c0a4b4e10795d22dd8b2609e519e10ab90adf9e74ad2007bd51010000008000000000000000000000006436877a29ba610553ec89ffc3865d5a6b16ad0af0ba094a3dda6e3e9878ff556436877a95153dbf344fbf78c42ddf5dad8eec94a85ea328b812e66a5b0594ec10f935adc57425e1b214f8640d56e0c733000000000000000000000000010000000000000003000001000000000001000000".decodeHex()

    @Setup
    fun setUp() {
        (LoggerFactory.getLogger(Logger.ROOT_LOGGER_NAME) as Logger).level = Level.WARN
        (LoggerFactory.getLogger("org.opencoap.ssl") as Logger).level = Level.WARN

        smallMessage = Random.nextBytes(64)
        largeMessage = Random.nextBytes(1280)

        clientSession = clientConf.loadSession(byteArrayOf(), cliSession, localAddress(2_5684))
        serverSession = serverConf.loadSession(byteArrayOf(), srvSession, localAddress(1_5684))
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
        bh.consume(serverSession.encrypt(largeMessage))
    }

    @Benchmark
    fun encrypt_and_decrypt_1kb(bh: Blackhole) {
        val encryptedMsg: ByteBuffer = clientSession.encrypt(largeMessage)
        val plainMsg = serverSession.decrypt(encryptedMsg)

        bh.consume(encryptedMsg)
        bh.consume(plainMsg)
    }

    private var sendingBuffer: ByteBuffer? = null
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
        val session = serverConf.loadSession(byteArrayOf(), srvSession, localAddress(1_5684))
        val sessionData = session.saveAndClose()

        bh.consume(sessionData)
    }
}
