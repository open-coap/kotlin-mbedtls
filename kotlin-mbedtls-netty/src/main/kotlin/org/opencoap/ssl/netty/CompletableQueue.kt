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

package org.opencoap.ssl.netty

import java.util.LinkedList
import java.util.concurrent.CompletableFuture

internal class CompletableQueue<T> {
    private val queue = LinkedList<CompletableFuture<T>>()

    @Synchronized
    fun add(obj: T) {
        if (!queue.isEmpty() && !queue.first.isDone) {
            queue.removeFirst().complete(obj)
        } else {
            queue.addLast(CompletableFuture.completedFuture(obj))
        }
    }

    @Synchronized
    fun poll(): CompletableFuture<T> {
        if (!queue.isEmpty() && queue.first.isDone) {
            return queue.removeFirst()
        }
        val promise = CompletableFuture<T>()
        queue.addLast(promise)
        return promise
    }

    fun cancelAll() {
        queue.forEach { it.cancel(false) }
        queue.clear()
    }
}
