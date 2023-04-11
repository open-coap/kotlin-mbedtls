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

import org.junit.jupiter.api.Assertions.assertEquals
import org.opencoap.ssl.CertificateAuth
import org.opencoap.ssl.RandomCidSupplier
import org.opencoap.ssl.SslConfig
import org.opencoap.ssl.transport.BytesPacket
import org.opencoap.ssl.transport.Certs
import org.opencoap.ssl.transport.DtlsServerTransport
import org.opencoap.ssl.transport.DtlsTransmitter
import org.opencoap.ssl.transport.listen
import org.opencoap.ssl.util.await
import org.openjdk.jmh.annotations.Benchmark
import org.openjdk.jmh.annotations.Fork
import org.openjdk.jmh.annotations.Measurement
import org.openjdk.jmh.annotations.OperationsPerInvocation
import org.openjdk.jmh.annotations.Scope
import org.openjdk.jmh.annotations.Setup
import org.openjdk.jmh.annotations.State
import org.openjdk.jmh.annotations.TearDown
import org.openjdk.jmh.annotations.Threads
import org.openjdk.jmh.annotations.Warmup
import org.openjdk.jmh.infra.Blackhole
import java.util.function.Consumer
import kotlin.random.Random

@State(Scope.Benchmark)
@Fork(1)
@Threads(1)
@Warmup(iterations = 1, time = 5)
@Measurement(iterations = 4, time = 5)
open class DtlsServerTransportBenchmark {

    val serverConf = SslConfig.server(CertificateAuth(Certs.serverChain, Certs.server.privateKey), reqAuthentication = false, cidSupplier = RandomCidSupplier(16), cipherSuites = listOf("TLS-ECDHE-ECDSA-WITH-AES-128-GCM-SHA256"))
    val clientConf = SslConfig.client(CertificateAuth.trusted(Certs.root.asX509()), cipherSuites = listOf("TLS-ECDHE-ECDSA-WITH-AES-128-GCM-SHA256"))

    private val echoMessage = "echo:".encodeToByteArray()
    private val echoHandler: Consumer<BytesPacket> = Consumer<BytesPacket> { packet ->
        val resp = packet.map { echoMessage.plus(it) }
        server.send(resp)
    }
    lateinit var server: DtlsServerTransport
    lateinit var client: DtlsTransmitter
    private val message = Random.nextBytes(1280) // usual IP MTU

    @Setup
    fun setUp() {
        server = DtlsServerTransport.create(serverConf).also { it.listen(echoHandler, it.executor()) }
        client = DtlsTransmitter.connect(server, clientConf).await()
    }

    @TearDown
    fun tearDown() {
        client.close()
        server.close()

        clientConf.close()
        serverConf.close()
    }

    @Benchmark
    @OperationsPerInvocation(1)
    fun exchange_1k_message(bh: Blackhole) {
        client.send(message)

        val received = client.receive().await()
        bh.consume(received)
        assertEquals(message.size + echoMessage.size, received.size)
    }

    companion object {
        const val maxTransactions = 20
    }

    @Benchmark
    @OperationsPerInvocation(maxTransactions)
    fun exchange_1k_messages_20_concurrent_transactions(bh: Blackhole) {
        repeat(maxTransactions) {
            client.send(message)
        }

        repeat(maxTransactions) {
            val received = client.receive().await()
            bh.consume(received)
            // assertEquals(cliMessage.size + echoMessage.size, received.size)
        }
    }
}
