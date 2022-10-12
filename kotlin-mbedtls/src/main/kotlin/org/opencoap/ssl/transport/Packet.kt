/*
 * Copyright (c) 2022 kotlin-mbedtls contributors (https://github.com/open-coap/kotlin-mbedtls)
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

package org.opencoap.ssl.transport

import java.net.InetSocketAddress
import java.nio.ByteBuffer

data class Packet<T>(val buffer: T, val peerAddress: InetSocketAddress) {
    fun <T2> map(f: (T) -> T2): Packet<T2> = Packet(f(buffer), peerAddress)

    companion object {
        val EmptyByteBufferPacket: ByteBufferPacket = Packet(ByteBuffer.allocate(0), InetSocketAddress.createUnresolved("", 0))
        val EmptyBytesPacket: BytesPacket = Packet(byteArrayOf(), InetSocketAddress.createUnresolved("", 0))
    }
}

typealias ByteBufferPacket = Packet<ByteBuffer>

typealias BytesPacket = Packet<ByteArray>
