/*
 * Copyright (c) 2022-2026 kotlin-mbedtls contributors (https://github.com/open-coap/kotlin-mbedtls)
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

package org.opencoap.ssl.jna

import com.sun.jna.Memory
import org.opencoap.ssl.Bio
import org.opencoap.ssl.NativeConf
import org.opencoap.ssl.NativeContext
import java.io.Closeable
import java.nio.ByteBuffer

/** JNA-backed native configuration handle. */
internal class JnaNativeConf(
    val conf: Memory,
    private val cleanup: () -> Unit
) : NativeConf,
    Closeable {
    override fun close() = cleanup()
}

/**
 * JNA-backed native context handle. Holds strong references to the [Bio] and the BIO callbacks so the
 * JVM does not garbage-collect them while native code still holds pointers to them.
 */
internal class JnaNativeContext(
    val sslContext: Memory,
    private val bio: Bio,
    private val sendCallback: SendCallback,
    private val receiveCallback: ReceiveCallback,
) : NativeContext {
    // Referenced to document and guarantee the GC-roots are retained.
    val retained: List<Any> get() = listOf(bio, sendCallback, receiveCallback, sslContext)
}

internal fun ByteBuffer.cloneToMemory(): Memory {
    this.mark() // saves the original position
    val remaining = this.remaining()
    val memory = Memory(remaining.toLong())
    val intermediateBuffer: ByteBuffer = memory.getByteBuffer(0, remaining.toLong())
    intermediateBuffer.put(this)
    this.reset()
    return memory
}
