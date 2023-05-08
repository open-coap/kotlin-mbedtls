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

package benchmark.netty

import io.netty.buffer.Unpooled
import io.netty.channel.Channel
import org.opencoap.ssl.CertificateAuth
import org.opencoap.ssl.RandomCidSupplier
import org.opencoap.ssl.SslConfig
import org.opencoap.ssl.netty.EchoHandler
import org.opencoap.ssl.netty.NettyHelpers
import org.opencoap.ssl.netty.NettyTransportAdapter
import org.opencoap.ssl.util.Certs
import org.opencoap.ssl.util.localAddress
import org.opencoap.ssl.util.seconds
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
import java.nio.ByteBuffer
import kotlin.random.Random

@State(Scope.Benchmark)
@Fork(1)
@Threads(1)
@Warmup(iterations = 1, time = 5)
@Measurement(iterations = 4, time = 5)
open class NettyBenchmark {

    private val serverConf = SslConfig.server(CertificateAuth(Certs.serverChain, Certs.server.privateKey), reqAuthentication = false, cidSupplier = RandomCidSupplier(16), cipherSuites = listOf("TLS-ECDHE-ECDSA-WITH-AES-128-GCM-SHA256"))
    private val clientConf = SslConfig.client(CertificateAuth.trusted(Certs.root.asX509()), cipherSuites = listOf("TLS-ECDHE-ECDSA-WITH-AES-128-GCM-SHA256"))
    private lateinit var serverChannel: Channel
    private lateinit var client: NettyTransportAdapter
    private val message = ByteBuffer.wrap(Random.nextBytes(1280)) // usual IP MTU
    private val heapBufMessage = Unpooled.wrappedBuffer(message)
    private val directBufMessage = Unpooled.directBuffer().writeBytes(message)

    @Setup
    fun setUp() {
        serverChannel = NettyHelpers.createBootstrap(5685, serverConf) { addLast("reply", EchoHandler()) }
            .bind().sync().channel()

        client = NettyTransportAdapter.connect(clientConf, localAddress(5685))
    }

    @TearDown
    fun tearDown() {
        serverChannel.close()

        clientConf.close()
        serverConf.close()
    }

    @Benchmark
    @OperationsPerInvocation(1)
    fun exchange_1k_message(bh: Blackhole) {
        client.send(heapBufMessage.retain())

        val received = client.receive(1.seconds).join()
        bh.consume(received)
        // Assertions.assertEquals(message.size + echoMessage.size, received.size)
    }

    @Benchmark
    @OperationsPerInvocation(1)
    fun exchange_1k_message_direct_buf(bh: Blackhole) {
        client.send(directBufMessage.retain())

        val received = client.receive(1.seconds).join()
        bh.consume(received)
        // Assertions.assertEquals(message.size + echoMessage.size, received.size)
    }

    @Benchmark
    @OperationsPerInvocation(maxTransactions)
    fun exchange_1k_messages_20_concurrent_transactions(bh: Blackhole) {
        repeat(maxTransactions) {
            client.send(heapBufMessage.retain())
        }

        repeat(maxTransactions) {
            val received = client.receive(1.seconds).join()
            bh.consume(received)
            // assertEquals(cliMessage.size + echoMessage.size, received.size)
        }
    }

    @Benchmark
    @OperationsPerInvocation(maxTransactions)
    fun exchange_1k_messages_20_concurrent_transactions_direct_buf(bh: Blackhole) {
        repeat(maxTransactions) {
            client.send(directBufMessage.retain())
        }

        repeat(maxTransactions) {
            val received = client.receive(1.seconds).join()
            bh.consume(received)
            // assertEquals(cliMessage.size + echoMessage.size, received.size)
        }
    }

    companion object {
        const val maxTransactions = 20
    }
}
