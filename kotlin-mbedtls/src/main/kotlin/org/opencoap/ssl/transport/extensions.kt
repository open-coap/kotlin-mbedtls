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

import java.nio.ByteBuffer
import java.time.Duration
import java.util.concurrent.CompletableFuture
import java.util.concurrent.Executor
import java.util.concurrent.ScheduledExecutorService
import java.util.concurrent.ScheduledFuture
import java.util.concurrent.TimeUnit
import java.util.function.Supplier

internal fun <T> Executor.supply(supplier: Supplier<T>): CompletableFuture<T> {
    return CompletableFuture.supplyAsync(supplier, this)
}

internal fun ScheduledExecutorService.schedule(task: Runnable, delay: Duration): ScheduledFuture<*> {
    return this.schedule(task, delay.toMillis(), TimeUnit.MILLISECONDS)
}

internal fun ByteArray.toHex(): String {
    return joinToString(separator = "") { eachByte -> "%02x".format(eachByte) }
}

fun ByteBuffer.copyDirect(): ByteBuffer {
    val bb = ByteBuffer.allocateDirect(this.remaining())
    bb.put(this)
    bb.flip()
    return bb
}
