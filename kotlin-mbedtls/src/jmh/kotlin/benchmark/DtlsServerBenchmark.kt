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
import org.opencoap.ssl.EmptyCidSupplier
import org.opencoap.ssl.PskAuth
import org.opencoap.ssl.RandomCidSupplier
import org.opencoap.ssl.SslConfig
import org.opencoap.ssl.transport.BytesPacket
import org.opencoap.ssl.transport.DtlsServer
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
@Measurement(iterations = 1, time = 20)
open class DtlsServerBenchmark {
    private val psk = PskAuth("dupa", byteArrayOf(1))
    private val conf: SslConfig = SslConfig.server(psk, cidSupplier = RandomCidSupplier(6))
    private val clientConfig = SslConfig.client(psk, cidSupplier = EmptyCidSupplier)

    private val echoMessage = "echo:".encodeToByteArray()
    private val echoHandler: Consumer<BytesPacket> = Consumer<BytesPacket> { packet ->
        val resp = packet.map { echoMessage.plus(it) }
        server.send(resp)
    }
    lateinit var server: DtlsServer
    lateinit var client: DtlsTransmitter
    private val cliMessage = Random.nextBytes(7)

    @Setup
    fun setUp() {
        server = DtlsServer.create(conf).also { it.listen(echoHandler, it.executor()) }
        client = DtlsTransmitter.connect(server, clientConfig).await()
    }

    @TearDown
    fun tearDown() {
        client.close()
        server.close()
    }

    @Benchmark
    @OperationsPerInvocation(1)
    fun exchange_messages(bh: Blackhole) {
        client.send(cliMessage)

        val received = client.receive().await()
        bh.consume(received)
        assertEquals(cliMessage.size + echoMessage.size, received.size)
    }

    companion object {
        const val maxTransactions = 20
    }

    @Benchmark
    @OperationsPerInvocation(maxTransactions)
    fun exchange_messages_20_concurrent_transactions(bh: Blackhole) {
        repeat(maxTransactions) {
            client.send(cliMessage)
        }

        repeat(maxTransactions) {
            val received = client.receive().await()
            bh.consume(received)
            // assertEquals(cliMessage.size + echoMessage.size, received.size)
        }
    }
}
