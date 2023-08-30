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

import io.mockk.Called
import io.mockk.confirmVerified
import io.mockk.mockk
import io.mockk.verify
import org.junit.jupiter.api.Test
import org.opencoap.ssl.transport.DtlsSessionLifecycleCallbacks.Reason
import org.opencoap.ssl.util.localAddress
import java.util.concurrent.Executors

class AsyncDtlsSessionLifecycleCallbacksTest {

    @Test
    fun `should invoke callbacks`() {
        val callbackMock = mockk<DtlsSessionLifecycleCallbacks>()
        val asyncCallbacks = callbackMock.toAsync(Executors.newSingleThreadExecutor())

        // when
        asyncCallbacks.handshakeStarted(localAddress(5683))
        asyncCallbacks.handshakeFinished(localAddress(5683), 0, 1, Reason.SUCCEEDED)
        asyncCallbacks.sessionStarted(localAddress(5683), "A", false)
        asyncCallbacks.sessionFinished(localAddress(5683), Reason.CLOSED)

        Thread.sleep(500)

        // then
        verify {
            callbackMock.handshakeStarted(any())
            callbackMock.handshakeFinished(any(), 0, 1, Reason.SUCCEEDED)
            callbackMock.sessionStarted(any(), "A", false)
            callbackMock.sessionFinished(any(), Reason.CLOSED)
        }
        confirmVerified(callbackMock)
    }

    @Test
    fun `should not invoke callbacks with non operational executor`() {
        val callbackMock = mockk<DtlsSessionLifecycleCallbacks>()
        val asyncCallbacks = callbackMock.toAsync {}

        // when
        asyncCallbacks.handshakeStarted(localAddress(5683))
        asyncCallbacks.handshakeFinished(localAddress(5683), 0, 1, Reason.SUCCEEDED)
        asyncCallbacks.sessionStarted(localAddress(5683), "A", false)
        asyncCallbacks.sessionFinished(localAddress(5683), Reason.CLOSED)

        Thread.sleep(500)

        // then
        verify {
            callbackMock wasNot Called
        }
        confirmVerified(callbackMock)
    }
}
