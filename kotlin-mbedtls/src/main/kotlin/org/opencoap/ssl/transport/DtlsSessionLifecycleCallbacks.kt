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

import java.net.InetSocketAddress
import java.util.concurrent.Executor

interface DtlsSessionLifecycleCallbacks {
    enum class Reason {
        SUCCEEDED, FAILED, CLOSED, EXPIRED
    }

    fun handshakeStarted(adr: InetSocketAddress) = Unit
    fun handshakeFinished(adr: InetSocketAddress, hanshakeStartTimestamp: Long, hanshakeFinishTimestamp: Long, reason: Reason, throwable: Throwable? = null) =
        Unit

    fun sessionStarted(adr: InetSocketAddress, cipherSuite: String, reloaded: Boolean) = Unit
    fun sessionFinished(adr: InetSocketAddress, reason: Reason, throwable: Throwable? = null) = Unit

    fun messageDropped(adr: InetSocketAddress) = Unit
}

class AsyncDtlsSessionLifecycleCallbacks(private val executor: Executor, private val callbacks: DtlsSessionLifecycleCallbacks) :
    DtlsSessionLifecycleCallbacks {

    override fun handshakeStarted(adr: InetSocketAddress) {
        executor.supply { callbacks.handshakeStarted(adr) }
    }

    override fun handshakeFinished(adr: InetSocketAddress, hanshakeStartTimestamp: Long, hanshakeFinishTimestamp: Long, reason: DtlsSessionLifecycleCallbacks.Reason, throwable: Throwable?) {
        executor.supply { callbacks.handshakeFinished(adr, hanshakeStartTimestamp, hanshakeFinishTimestamp, reason, throwable) }
    }

    override fun sessionStarted(adr: InetSocketAddress, cipherSuite: String, reloaded: Boolean) {
        executor.supply { callbacks.sessionStarted(adr, cipherSuite, reloaded) }
    }

    override fun sessionFinished(adr: InetSocketAddress, reason: DtlsSessionLifecycleCallbacks.Reason, throwable: Throwable?) {
        executor.supply { callbacks.sessionFinished(adr, reason, throwable) }
    }

    override fun messageDropped(adr: InetSocketAddress) {
        executor.supply { callbacks.messageDropped(adr) }
    }
}

fun DtlsSessionLifecycleCallbacks.toAsync(executor: Executor): DtlsSessionLifecycleCallbacks =
    AsyncDtlsSessionLifecycleCallbacks(executor, this)
