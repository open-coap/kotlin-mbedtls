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

import org.opencoap.ssl.util.Certificate

internal object Certs {
    val root = Certificate.createRootEC("root-ca")
    val server = root.signNew("server", false)
    val serverChain = listOf(server, root).map(Certificate::asX509)

    val rootRsa = Certificate.createRootRSA("root-ca2")
    val int1 = rootRsa.signNew("intermediate-1", true)
    val int2 = int1.signNew("intermediate-2", true)
    val server2 = int2.signNew("server2", false)
    val serverLongChain = listOf(server2, int2, int1, rootRsa).map(Certificate::asX509)

    val int1a = rootRsa.signNew("intermediate-1a", true)

    val dev01 = root.signNew("device01", false)
    val dev01Chain = listOf(dev01.asX509(), root.asX509())

    val dev99 = Certificate.createRootEC("device99")
    val dev99Chain = listOf(dev99.asX509())
}
