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

package org.opencoap.ssl.netty

import io.netty.channel.ChannelHandlerContext
import io.netty.channel.ChannelInboundHandlerAdapter
import io.netty.channel.socket.DatagramChannel
import io.netty.util.ReferenceCountUtil
import org.junit.jupiter.api.AfterAll
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestInstance
import org.opencoap.ssl.CertificateAuth
import org.opencoap.ssl.RandomCidSupplier
import org.opencoap.ssl.SslConfig
import org.opencoap.ssl.netty.NettyHelpers.createBootstrap
import org.opencoap.ssl.util.Certs
import org.opencoap.ssl.util.await
import org.opencoap.ssl.util.localAddress
import org.opencoap.ssl.util.millis
import org.opencoap.ssl.util.seconds
import java.net.InetSocketAddress

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class NettyRetransmissionTestTest {

    private val serverConf = SslConfig.server(CertificateAuth(Certs.serverChain, Certs.server.privateKey), listOf("TLS-ECDHE-ECDSA-WITH-AES-128-GCM-SHA256"), false, cidSupplier = RandomCidSupplier(6), retransmitMin = 100.millis)
    private val clientConf = SslConfig.client(CertificateAuth.trusted(Certs.root.asX509()), retransmitMin = 200.millis)
    private lateinit var udpChannel: DatagramChannel
    private val srvAddress: InetSocketAddress by lazy { localAddress(udpChannel.localAddress().port) }

    @BeforeAll
    fun beforeAll() {
        udpChannel = createBootstrap(0, DtlsChannelHandler(serverConf)) { addLast("echo", EchoHandler()) }.bind().sync().channel() as DatagramChannel
    }

    @AfterAll
    fun afterAll() {
        udpChannel.close().sync()
        serverConf.close()
    }

    @Test
    fun `should handshake with retransmission`() {
        udpChannel.pipeline().addFirst("DROPPING", DroppingHandler())

        // connect and handshake
        val client = NettyTransportAdapter.connect(clientConf, srvAddress).mapToString()

        assertTrue(client.send("hi").await())
        assertEquals("ECHO:hi", client.receive(5.seconds).await())

        client.close()
        udpChannel.pipeline().remove("DROPPING")
    }
}

class DroppingHandler : ChannelInboundHandlerAdapter() {
    private var index = 0

    override fun channelRead(ctx: ChannelHandlerContext, msg: Any) {
        if (index++ == 2) {
            println("DROPPED: $msg")
            ReferenceCountUtil.release(msg)
        } else {
            println("IN       $msg")
            ctx.fireChannelRead(msg)
        }
    }
}
