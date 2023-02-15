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

package org.opencoap.ssl.transport.metrics.micrometer

import io.micrometer.core.instrument.Counter
import io.micrometer.core.instrument.MeterRegistry
import org.opencoap.ssl.HelloVerifyRequired
import org.opencoap.ssl.SslHandshakeContext
import org.opencoap.ssl.SslSession
import org.opencoap.ssl.transport.DtlsServer
import java.net.InetSocketAddress
import java.util.concurrent.TimeUnit

class DtlsServerMetricsCallbacks(private val registry: MeterRegistry, metricsPrefix: String = "dtls.server") : DtlsServer.DtlsSessionLifecycleCallbacks {
    private val handshakesInitiated = registry.counter("${metricsPrefix}.handshakes.initiated")
    private val handshakesSucceeded = registry.timer("${metricsPrefix}.handshakes.succeeded")
    private val handshakesFailedBuilder = Counter.builder("${metricsPrefix}.handshakes.failed")
    private val handshakesExpired = registry.counter("${metricsPrefix}.handshakes.expired")
    private val sessionsStartedBuilder = Counter.builder("${metricsPrefix}.sessions.started")
    private val sessionsClosed = registry.counter("${metricsPrefix}.sessions.closed")
    private val sessionsFailedBuilder = Counter.builder("${metricsPrefix}.sessions.failed")
    private val sessionsExpired = registry.counter("${metricsPrefix}.sessions.expired")
    private val sessionsReloaded = registry.counter("${metricsPrefix}.sessions.reloaded")

    override fun handshakeStarted(adr: InetSocketAddress, ctx: SslHandshakeContext) {
        handshakesInitiated.increment()
    }

    override fun handshakeFinished(adr: InetSocketAddress, ctx: SslHandshakeContext, reason: DtlsServer.DtlsSessionLifecycleCallbacks.Reason, throwable: Throwable?) = when(reason) {
        DtlsServer.DtlsSessionLifecycleCallbacks.Reason.SUCCEEDED ->
            handshakesSucceeded.record(System.currentTimeMillis() - ctx.startTimestamp, TimeUnit.MILLISECONDS)
        DtlsServer.DtlsSessionLifecycleCallbacks.Reason.FAILED ->
            if (throwable is HelloVerifyRequired) {
                // Skip HelloVerifyRequired handshake states
            } else {
                val reasonTag = when(throwable) {
                    null -> "n/a"
                    else -> throwable::class.toString()
                }
                handshakesFailedBuilder.tag("reason", reasonTag).register(registry).increment()
            }
        DtlsServer.DtlsSessionLifecycleCallbacks.Reason.EXPIRED ->
            handshakesExpired.increment()
        else -> {}
    }

    override fun sessionStarted(adr: InetSocketAddress, ctx: SslSession) = if (ctx.reloaded) {
        sessionsReloaded.increment()
    } else {
        sessionsStartedBuilder.tag("suite", ctx.cipherSuite).register(registry).increment()
    }

    override fun sessionFinished(adr: InetSocketAddress, ctx: SslSession, reason: DtlsServer.DtlsSessionLifecycleCallbacks.Reason, throwable: Throwable?) = when(reason) {
        DtlsServer.DtlsSessionLifecycleCallbacks.Reason.FAILED -> {
            val reasonTag = when(throwable) {
                null -> "n/a"
                else -> throwable::class.toString()
            }
            sessionsFailedBuilder.tag("reason", reasonTag).register(registry).increment()
        }
        DtlsServer.DtlsSessionLifecycleCallbacks.Reason.CLOSED ->
            sessionsClosed.increment()
        DtlsServer.DtlsSessionLifecycleCallbacks.Reason.EXPIRED ->
            sessionsExpired.increment()
        else -> {}
    }
}
