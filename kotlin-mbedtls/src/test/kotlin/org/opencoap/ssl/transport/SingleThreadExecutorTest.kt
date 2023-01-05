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

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test
import java.util.concurrent.TimeUnit

class SingleThreadExecutorTest {

    @Volatile
    private var test = ""

    @Test
    fun `should run immediately when executed from same thread`() {
        val executor = SingleThreadExecutor.create("test")

        executor.supply {
            executor.execute { test += "11" }
            test += "22"
            executor.execute { test += "33" }
            test += "44"
        }.get()

        executor.shutdown()
        executor.awaitTermination(10, TimeUnit.SECONDS)

        assertEquals("11223344", test)
    }
}
