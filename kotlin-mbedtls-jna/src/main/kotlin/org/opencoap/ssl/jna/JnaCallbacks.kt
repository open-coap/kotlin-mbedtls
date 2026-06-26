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

import com.sun.jna.Callback
import com.sun.jna.Pointer
import org.opencoap.ssl.Bio
import org.slf4j.LoggerFactory

/**
 * Native receive (recv_timeout) callback. Converts the native destination pointer to a [java.nio.ByteBuffer]
 * view and delegates the orchestration to the core-owned [Bio].
 */
internal class ReceiveCallback(private val bio: Bio) : Callback {
    fun callback(ctx: Pointer?, bufPointer: Pointer, len: Int, timeout: Int): Int {
        val dst = bufPointer.getByteBuffer(0, len.toLong())
        return bio.onReceive(dst, len, timeout)
    }
}

/**
 * Native send callback. Converts the native source pointer to a [java.nio.ByteBuffer] view and delegates to [Bio].
 */
internal class SendCallback(private val bio: Bio) : Callback {
    fun callback(ctx: Pointer?, buf: Pointer, len: Int): Int {
        val src = buf.getByteBuffer(0, len.toLong())
        return bio.onSend(src, len)
    }
}

internal object LogCallback : Callback {
    private val logger = LoggerFactory.getLogger(MbedtlsApi::class.java)

    @Suppress("ReturnCount")
    fun callback(ctx: Pointer?, debugLevel: Int, fileName: String, lineNumber: Int, message: String?) {
        if (debugLevel == 1) {
            // Introduced in MbedTLS 4.0.0: this log message should be at trace level, not warning
            // These should be fixed in the next MbedTLS release of 4.x
            if (message?.contains("Perform PSA-based ECDH computation") == true) return
            if (message?.contains("<= mbedtls_ssl_check_record") == true) return
            if (message?.contains("=> mbedtls_ssl_check_record") == true) return

            // logs when close notify is received
            if (message?.contains("mbedtls_ssl_handle_message_type() returned -30848 (-0x7880)") == true) return
            if (message?.contains("mbedtls_ssl_read_record() returned -30848 (-0x7880)") == true) return
        }

        when (debugLevel) {
            1 -> logger.warn("[mbedtls {}:{}] {} ", fileName.substringAfterLast('/'), lineNumber, message?.trim())
            2 -> logger.debug("[mbedtls {}:{}] {}", fileName.substringAfterLast('/'), lineNumber, message?.trim())
            else -> logger.trace("[mbedtls {}:{}] {}", fileName.substringAfterLast('/'), lineNumber, message?.trim())
        }
    }
}

internal object NoOpsSetDelayCallback : Callback {
    @Suppress("UnusedParameter")
    fun callback(data: Pointer?, intermediateMs: Int, finalMs: Int) {
        // do nothing
    }
}

internal object NoOpsGetDelayCallback : Callback {
    @Suppress("FunctionOnlyReturningConstant", "UnusedParameter")
    fun callback(data: Pointer?): Int = 1
}
