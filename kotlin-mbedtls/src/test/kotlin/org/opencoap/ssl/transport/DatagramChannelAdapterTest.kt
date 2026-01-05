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
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import org.opencoap.ssl.util.await
import org.opencoap.ssl.util.localAddress
import org.opencoap.ssl.util.millis
import org.opencoap.ssl.util.seconds
import java.nio.ByteBuffer
import java.util.concurrent.CompletionException
import java.util.concurrent.RejectedExecutionException

class DatagramChannelAdapterTest {

    @Test
    fun sendAndReceive() {
        val trans1 = DatagramChannelAdapter.open()
        val trans2 = DatagramChannelAdapter.open()

        // when
        assertTrue(trans1.send(Packet("dupa".toByteBuffer(), trans2.localAddress())).join())

        // then
        val resp = trans2.receive(1.seconds).join()
        assertEquals("dupa", resp?.buffer?.decodeToString())

        trans1.close()
        trans2.close()
    }

    @Test
    fun cancelWhenClosing() {
        val trans = DatagramChannelAdapter.open()
        val received = trans.receive(1.seconds)
        assertFalse(received.isDone)

        // when
        trans.close()

        // then
        assertThrows<CompletionException> { received.join() }
        assertThrows<RejectedExecutionException> { trans.receive(1.seconds) }
    }

    @Test
    fun timeout() {
        val trans = DatagramChannelAdapter.open()

        // when
        val received = trans.receive(1.millis)

        // then
        assertEquals(Packet.EmptyByteBufferPacket, received.await())
        trans.close()
    }

    @Test
    fun listen() {
        val trans = DatagramChannelAdapter.open()
        trans.listen({ packet ->
            trans.send(packet.map(ByteBuffer::decodeToString).map { "echo:$it" }.map(String::toByteBuffer))
        })
        val cli = DatagramChannelAdapter.open()

        for (i in 1..10) {
            cli.send(Packet("$i:dupa".toByteBuffer(), trans.localAddress()))
        }

        for (i in 1..10) {
            assertEquals("echo:$i:dupa", cli.receive(1.seconds).await().buffer.decodeToString())
        }

        trans.close()
        cli.close()
    }
}
