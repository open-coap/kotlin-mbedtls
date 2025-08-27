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

import io.netty.channel.ChannelDuplexHandler
import io.netty.channel.ChannelHandlerContext
import io.netty.channel.ChannelPromise
import io.netty.channel.socket.DatagramPacket
import org.opencoap.ssl.SslException
import org.opencoap.ssl.SslSession
import org.opencoap.ssl.transport.SessionWriter
import org.slf4j.LoggerFactory

class DtlsClientChannelHandler(private val sslSession: SslSession, private val sessionWriter: SessionWriter) : ChannelDuplexHandler() {
    private val logger = LoggerFactory.getLogger(javaClass)
    private lateinit var ctx: ChannelHandlerContext

    override fun handlerAdded(ctx: ChannelHandlerContext) {
        this.ctx = ctx
    }

    override fun close(ctx: ChannelHandlerContext, promise: ChannelPromise) {
        try {
            val cid = sslSession.ownCid
            if (cid != null && sessionWriter != SessionWriter.NO_OPS) {
                sessionWriter(cid, sslSession.saveAndClose())
            } else {
                sslSession.close()
            }
        } catch (ex: Exception) {
            logger.warn("Could not store session: {}", ex.toString())
        }
        ctx.close(promise)
    }

    override fun channelRead(ctx: ChannelHandlerContext, msg: Any) {
        if (msg !is DatagramPacket) {
            ctx.fireChannelRead(msg)
            return
        }

        val plainContent = ctx.alloc().buffer(msg.content().readableBytes())
        try {
            plainContent.writeThroughNioBuffer {
                sslSession.decrypt(msg.content().nioBuffer(), it) { }
            }

            if (plainContent.isReadable) {
                ctx.fireChannelRead(msg.replace(plainContent.retain()))
            }
        } catch (ex: SslException) {
            logger.warn("[{}], {}", msg.sender(), ex.toString())
        } finally {
            plainContent.release()
            msg.release()
        }
    }

    override fun write(ctx: ChannelHandlerContext, msg: Any, promise: ChannelPromise) {
        if (msg !is DatagramPacket) {
            ctx.write(msg, promise)
            return
        }

        msg.useAndRelease {
            val content = it.content()
            val dtlsPacket = sslSession.encrypt(content.nioBuffer())

            ctx.write(msg.replace(dtlsPacket.toByteBuf()), promise)
        }
    }
}
