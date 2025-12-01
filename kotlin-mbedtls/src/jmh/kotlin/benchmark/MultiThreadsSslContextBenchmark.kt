/*
 * Copyright (c) 2022-2025 kotlin-mbedtls contributors (https://github.com/open-coap/kotlin-mbedtls)
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

package benchmark

import org.opencoap.ssl.SslException
import org.openjdk.jmh.annotations.Fork
import org.openjdk.jmh.annotations.Measurement
import org.openjdk.jmh.annotations.Scope
import org.openjdk.jmh.annotations.State
import org.openjdk.jmh.annotations.Threads
import org.openjdk.jmh.annotations.Warmup
import org.openjdk.jmh.infra.Blackhole

@State(Scope.Thread)
@Fork(value = 1, jvmArgsPrepend = ["-Xms128m", "-Xmx128m"])
@Threads(8)
@Warmup(iterations = 1, time = 2)
@Measurement(iterations = 1, time = 5)
open class MultiThreadsSslContextBenchmark : SslContextBenchmark() {

    override fun load_and_save_ssl_session(bh: Blackhole) {
        try {
            super.load_and_save_ssl_session(bh)
        } catch (_: SslException) {
            // Ignore exceptions due to concurrent access
        }
    }
}
