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

package org.opencoap.ssl.util

import org.opencoap.ssl.CertificateAuth
import org.opencoap.ssl.RandomCidSupplier
import org.opencoap.ssl.SslConfig
import org.opencoap.ssl.transport.DatagramChannelAdapter
import org.opencoap.ssl.transport.DtlsTransmitter
import java.time.Duration

object StoredSessionPair {
    val cliSession: ByteArray
    val srvSession: ByteArray
    val cid: ByteArray

    init {
        // copied from DtlsTransmitterCertTest.`should successfully handshake with server only cert`

        val serverConf = SslConfig.server(CertificateAuth(Certs.serverChain, Certs.server.privateKey), reqAuthentication = false, cidSupplier = RandomCidSupplier(16), cipherSuites = listOf("TLS-ECDHE-ECDSA-WITH-AES-128-GCM-SHA256"))
        val srvTrans = DatagramChannelAdapter.connect(localAddress(7099), 0)
        val server = DtlsTransmitter.connect(localAddress(7099), serverConf, srvTrans)

        val clientConf = SslConfig.client(CertificateAuth.trusted(Certs.root.asX509()), cipherSuites = listOf("TLS-ECDHE-ECDSA-WITH-AES-128-GCM-SHA256"))
        val client = DtlsTransmitter.connect(srvTrans, clientConf, 7099).await()

        client.send("dupa")
        server.await().receive(Duration.ofSeconds(5)).get()

        cliSession = client.saveSession()
        srvSession = server.await().saveSession()
        cid = server.await().ownCid!!
    }
}
