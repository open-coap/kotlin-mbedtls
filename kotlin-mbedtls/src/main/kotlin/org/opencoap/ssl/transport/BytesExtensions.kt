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

package org.opencoap.ssl.transport

import com.sun.jna.Memory
import java.nio.ByteBuffer

internal fun ByteArray.toHex(): String {
    return joinToString(separator = "") { eachByte -> "%02x".format(eachByte) }
}

fun ByteBuffer.copy(): ByteBuffer {
    val bb = ByteBuffer.allocateDirect(this.remaining())
    bb.put(this)
    bb.flip()
    return bb
}

fun ByteBuffer.cloneToMemory(): Memory {
    this.mark() // saves the original position
    val remaining = this.remaining()
    val memory = Memory(remaining.toLong())
    val intermediateBuffer: ByteBuffer = memory.getByteBuffer(0, remaining.toLong())
    intermediateBuffer.put(this)
    this.reset()
    return memory
}

fun ByteBuffer.isNotEmpty(): Boolean = this.hasRemaining()
fun ByteBuffer.isEmpty(): Boolean = !this.hasRemaining()

fun ByteArray.asByteBuffer(): ByteBuffer = ByteBuffer.wrap(this)

fun String.toByteBuffer(): ByteBuffer = this.encodeToByteArray().asByteBuffer()

fun ByteBuffer.decodeToString(): String {
    val bb = ByteArray(this.remaining())
    this.get(bb)
    return bb.decodeToString()
}
