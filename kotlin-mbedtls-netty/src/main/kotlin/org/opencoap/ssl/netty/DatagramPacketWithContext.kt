/*
 * Copyright (c) 2022-2024 kotlin-mbedtls contributors (https://github.com/open-coap/kotlin-mbedtls)
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

import io.netty.buffer.ByteBuf
import io.netty.channel.socket.DatagramPacket
import org.opencoap.ssl.transport.ByteBufferPacket
import org.opencoap.ssl.transport.DtlsSessionContext
import java.net.InetSocketAddress

class DatagramPacketWithContext(
    data: ByteBuf,
    recipient: InetSocketAddress?,
    sender: InetSocketAddress?,
    val sessionContext: DtlsSessionContext
) : DatagramPacket(data, recipient, sender) {

    companion object {
        fun from(packet: ByteBufferPacket): DatagramPacketWithContext {
            return DatagramPacketWithContext(packet.buffer.toByteBuf(), null, packet.peerAddress, packet.sessionContext)
        }

        @JvmStatic
        fun contextFrom(msg: DatagramPacket): DtlsSessionContext = when (msg) {
            is DatagramPacketWithContext -> msg.sessionContext
            else -> DtlsSessionContext.EMPTY
        }
    }
}
