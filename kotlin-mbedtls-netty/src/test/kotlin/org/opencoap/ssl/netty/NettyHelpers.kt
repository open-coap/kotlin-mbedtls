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

import io.netty.bootstrap.Bootstrap
import io.netty.buffer.ByteBuf
import io.netty.channel.Channel
import io.netty.channel.ChannelInboundHandler
import io.netty.channel.ChannelInitializer
import io.netty.channel.ChannelPipeline
import io.netty.channel.EventLoopGroup
import io.netty.channel.nio.NioEventLoopGroup
import io.netty.channel.socket.DatagramChannel
import io.netty.channel.socket.nio.NioDatagramChannel
import io.netty.util.concurrent.DefaultThreadFactory
import java.nio.charset.Charset

object NettyHelpers {

    fun createBootstrap(port: Int, dtlsChannelHandler: DtlsChannelHandler, pipelineBuilder: ChannelPipeline.() -> Unit, bootstrapConfig: (Bootstrap) -> Unit = {}): Bootstrap {
        val group: EventLoopGroup = NioEventLoopGroup(1, DefaultThreadFactory("udp", true))

        return Bootstrap()
            .group(group)
            .localAddress(port)
            .channel(NioDatagramChannel::class.java)
            .handler(object : ChannelInitializer<DatagramChannel>() {
                override fun initChannel(ch: DatagramChannel) {
                    ch.pipeline().addFirst("DTLS", dtlsChannelHandler)
                    pipelineBuilder(ch.pipeline())
                }
            })
            .also(bootstrapConfig::invoke)
    }
}

fun ByteBuf.writeString(text: String): ByteBuf {
    val len = writeCharSequence(text, Charset.defaultCharset())
    require(len == text.length)

    return this
}

fun Channel.channelRead(msg: Any) {
    val ctx = this.pipeline().firstContext()
    val inboundHandler = this.pipeline().first() as ChannelInboundHandler
    inboundHandler.channelRead(ctx, msg)
}
