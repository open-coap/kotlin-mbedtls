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
import io.micrometer.core.instrument.Meter
import io.micrometer.core.instrument.MeterRegistry
import io.micrometer.core.instrument.config.MeterFilter
import io.micrometer.core.instrument.distribution.DistributionStatisticConfig
import org.opencoap.ssl.HelloVerifyRequired
import org.opencoap.ssl.transport.DtlsSessionLifecycleCallbacks
import java.net.InetSocketAddress
import java.util.concurrent.TimeUnit

class DtlsServerMetricsCallbacks(
    private val registry: MeterRegistry,
    metricsPrefix: String = "dtls.server",
    private val distributionStatisticConfig: DistributionStatisticConfig =
        DistributionStatisticConfig.Builder().build(),
) : DtlsSessionLifecycleCallbacks {
    init {
        // Meter filter must be initialized before actual meters will be registered
        registry.config().meterFilter(object : MeterFilter {
            override fun configure(id: Meter.Id, config: DistributionStatisticConfig): DistributionStatisticConfig =
                if (id.name.startsWith("$metricsPrefix.handshakes.succeeded")) distributionStatisticConfig.merge(config) else config
        })
    }

    private val handshakesInitiated = registry.counter("$metricsPrefix.handshakes.initiated")
    private val handshakesSucceeded = registry.timer("$metricsPrefix.handshakes.succeeded")
    private val handshakesFailedBuilder = Counter.builder("$metricsPrefix.handshakes.failed")
    private val handshakesExpired = registry.counter("$metricsPrefix.handshakes.expired")
    private val sessionsStartedBuilder = Counter.builder("$metricsPrefix.sessions.started")
    private val sessionsClosed = registry.counter("$metricsPrefix.sessions.closed")
    private val sessionsFailedBuilder = Counter.builder("$metricsPrefix.sessions.failed")
    private val sessionsExpired = registry.counter("$metricsPrefix.sessions.expired")
    private val sessionsReloaded = registry.counter("$metricsPrefix.sessions.reloaded")

    override fun handshakeStarted(adr: InetSocketAddress) {
        handshakesInitiated.increment()
    }

    override fun handshakeFinished(adr: InetSocketAddress, hanshakeStartTimestamp: Long, reason: DtlsSessionLifecycleCallbacks.Reason, throwable: Throwable?) = when (reason) {
        DtlsSessionLifecycleCallbacks.Reason.SUCCEEDED ->
            handshakesSucceeded.record(System.currentTimeMillis() - hanshakeStartTimestamp, TimeUnit.MILLISECONDS)
        DtlsSessionLifecycleCallbacks.Reason.FAILED ->
            if (throwable is HelloVerifyRequired) {
                // Skip HelloVerifyRequired handshake states
            } else {
                handshakesFailedBuilder.reasonTag(throwable).register(registry).increment()
            }
        DtlsSessionLifecycleCallbacks.Reason.EXPIRED ->
            handshakesExpired.increment()
        else -> {}
    }

    override fun sessionStarted(adr: InetSocketAddress, cipherSuite: String, reloaded: Boolean) = if (reloaded) {
        sessionsReloaded.increment()
    } else {
        sessionsStartedBuilder.tag("suite", cipherSuite).register(registry).increment()
    }

    override fun sessionFinished(adr: InetSocketAddress, reason: DtlsSessionLifecycleCallbacks.Reason, throwable: Throwable?) = when (reason) {
        DtlsSessionLifecycleCallbacks.Reason.FAILED -> {
            sessionsFailedBuilder.reasonTag(throwable).register(registry).increment()
        }
        DtlsSessionLifecycleCallbacks.Reason.CLOSED ->
            sessionsClosed.increment()
        DtlsSessionLifecycleCallbacks.Reason.EXPIRED ->
            sessionsExpired.increment()
        else -> {}
    }
}

private fun Counter.Builder.reasonTag(throwable: Throwable?): Counter.Builder {
    val reason = when (throwable) {
        null -> "n/a"
        else -> throwable::class.qualifiedName ?: "n/a"
    }

    return this.tag("reason", reason)
}
