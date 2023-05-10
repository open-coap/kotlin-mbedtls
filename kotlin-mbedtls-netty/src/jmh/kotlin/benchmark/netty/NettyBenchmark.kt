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

import io.netty.bootstrap.Bootstrap
import io.netty.buffer.ByteBuf
import io.netty.buffer.ByteBufAllocator
import io.netty.buffer.PooledByteBufAllocator
import io.netty.buffer.Unpooled
import io.netty.buffer.UnpooledByteBufAllocator
import io.netty.channel.Channel
import io.netty.channel.ChannelOption
import org.opencoap.ssl.CertificateAuth
import org.opencoap.ssl.RandomCidSupplier
import org.opencoap.ssl.SslConfig
import org.opencoap.ssl.netty.DtlsChannelHandler
import org.opencoap.ssl.netty.EchoHandler
import org.opencoap.ssl.netty.NettyHelpers
import org.opencoap.ssl.netty.NettyTransportAdapter
import org.opencoap.ssl.util.Certs
import org.opencoap.ssl.util.seconds
import org.openjdk.jmh.annotations.Benchmark
import org.openjdk.jmh.annotations.Fork
import org.openjdk.jmh.annotations.Measurement
import org.openjdk.jmh.annotations.OperationsPerInvocation
import org.openjdk.jmh.annotations.Param
import org.openjdk.jmh.annotations.Scope
import org.openjdk.jmh.annotations.Setup
import org.openjdk.jmh.annotations.State
import org.openjdk.jmh.annotations.TearDown
import org.openjdk.jmh.annotations.Threads
import org.openjdk.jmh.annotations.Warmup
import org.openjdk.jmh.infra.Blackhole
import java.net.InetSocketAddress
import java.nio.ByteBuffer
import kotlin.random.Random

@State(Scope.Benchmark)
@Fork(value = 1, jvmArgsPrepend = ["-Xms128m", "-Xmx128m"])
@Threads(1)
@Warmup(iterations = 1, time = 5)
@Measurement(iterations = 1, time = 10)
open class NettyBenchmark {

    private val serverConf = SslConfig.server(CertificateAuth(Certs.serverChain, Certs.server.privateKey), reqAuthentication = false, cidSupplier = RandomCidSupplier(16), cipherSuites = listOf("TLS-ECDHE-ECDSA-WITH-AES-128-GCM-SHA256"))
    private val clientConf = SslConfig.client(CertificateAuth.trusted(Certs.root.asX509()), cipherSuites = listOf("TLS-ECDHE-ECDSA-WITH-AES-128-GCM-SHA256"))
    private lateinit var serverChannel: Channel
    private lateinit var client: NettyTransportAdapter
    private val message = ByteBuffer.wrap(Random.nextBytes(1280)) // usual IP MTU
    private lateinit var bufMessage: ByteBuf

    @Setup
    fun setUp(profile: TestProfile) {
        bufMessage = profile.wrap(message)

        serverChannel = NettyHelpers.createBootstrap(5685, DtlsChannelHandler(serverConf), { addLast("reply", EchoHandler()) }, profile::configure)
            .bind().sync().channel()

        client = NettyTransportAdapter.connect(clientConf, InetSocketAddress("127.0.0.1", 5685))
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
        client.send(bufMessage.retain())

        val received = client.receive(1.seconds).join()
        bh.consume(received)
        received.release()
        // Assertions.assertEquals(message.size + echoMessage.size, received.size)
    }

    @Benchmark
    @OperationsPerInvocation(maxTransactions)
    fun exchange_1k_messages_20_concurrent_transactions(bh: Blackhole) {
        repeat(maxTransactions) {
            client.send(bufMessage.retain())
        }

        repeat(maxTransactions) {
            val received = client.receive(1.seconds).join()
            bh.consume(received)
            received.release()
            // assertEquals(cliMessage.size + echoMessage.size, received.size)
        }
    }

    companion object {
        const val maxTransactions = 20
    }

    @State(Scope.Benchmark)
    open class TestProfile {
        @Param("direct", "heap", "unpooled")
        var bufAllocator = "heap"

        fun wrap(bb: ByteBuffer): ByteBuf {
            return when (bufAllocator) {
                "direct" -> Unpooled.directBuffer().writeBytes(bb)
                "heap", "unpooled" -> Unpooled.wrappedBuffer(bb)
                else -> throw IllegalArgumentException()
            }
        }

        fun configure(bootstrap: Bootstrap) {
            bootstrap.option(ChannelOption.ALLOCATOR, allocator())
        }

        private fun allocator(): ByteBufAllocator {
            return when (bufAllocator) {
                "direct" -> PooledByteBufAllocator(true)
                "unpooled" -> UnpooledByteBufAllocator(false)
                "heap" -> PooledByteBufAllocator(false)
                else -> throw IllegalArgumentException()
            }
        }
    }
}
