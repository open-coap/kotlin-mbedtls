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

import org.opencoap.ssl.SslHandshakeContext
import org.opencoap.ssl.SslSession
import java.net.InetSocketAddress

interface DtlsSessionLifecycleCallbacks {
    enum class Reason {
        SUCCEEDED, FAILED, CLOSED, EXPIRED
    }
    fun handshakeStarted(adr: InetSocketAddress, ctx: SslHandshakeContext) = Unit
    fun handshakeFinished(adr: InetSocketAddress, ctx: SslHandshakeContext, reason: Reason, throwable: Throwable? = null) = Unit
    fun sessionStarted(adr: InetSocketAddress, ctx: SslSession) = Unit
    fun sessionFinished(adr: InetSocketAddress, ctx: SslSession, reason: Reason, throwable: Throwable? = null) = Unit
}
