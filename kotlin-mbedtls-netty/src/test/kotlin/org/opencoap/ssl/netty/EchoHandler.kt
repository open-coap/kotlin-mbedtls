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

import io.netty.channel.ChannelHandler.Sharable
import io.netty.channel.ChannelHandlerContext
import io.netty.channel.ChannelInboundHandlerAdapter
import io.netty.channel.socket.DatagramPacket

@Sharable
class EchoHandler : ChannelInboundHandlerAdapter() {
    private val echoPrefix = "ECHO:".encodeToByteArray()
    override fun channelRead(ctx: ChannelHandlerContext, msg: Any) {
        val dgram = msg as DatagramPacket

        val sessionContext = DatagramPacketWithContext.contextFrom(msg)
        val authContext = (sessionContext.authenticationContext["AUTH"] ?: "").toByteArray()

        val reply = echoPrefix + authContext + dgram.content().toByteArray()
        dgram.release()

        ctx.writeAndFlush(DatagramPacket(reply.toByteBuf(), dgram.sender()))
    }
}
