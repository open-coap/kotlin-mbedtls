/*
 * Copyright (c) 2022-2024 kotlin-mbedtls contributors (https://github.com/open-coap/kotlin-mbedtls)
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

import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x500.X500NameBuilder
import org.bouncycastle.asn1.x500.style.BCStyle
import org.bouncycastle.asn1.x509.BasicConstraints
import org.bouncycastle.asn1.x509.Extension
import org.bouncycastle.cert.X509CertificateHolder
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import java.math.BigInteger
import java.security.KeyPairGenerator
import java.security.PrivateKey
import java.security.cert.X509Certificate
import java.time.Duration
import java.time.Instant
import java.util.Date

data class Certificate(
    val privateKey: PrivateKey,
    private val x509Cert: X509CertificateHolder,
    private val alg: String,
    private val signAlg: String,
    private val keySize: Int
) {

    fun asX509(): X509Certificate = converter.getCertificate(x509Cert)

    fun signNew(cnName: String, isCA: Boolean): Certificate = createCertificate(cnName, this, isCA, alg, signAlg, keySize)

    override fun toString(): String = "Certificate(subject: ${x509Cert.subject}, issuer: ${x509Cert.issuer})"

    companion object {
        private val converter = JcaX509CertificateConverter()

        fun createRootEC(cnName: String): Certificate = createCertificate(cnName, null, true, alg = "EC", signAlg = "SHA256withECDSA", 256)

        fun createRootRSA(cnName: String): Certificate = createCertificate(cnName, null, true, alg = "RSA", signAlg = "SHA256withRSA", 2048)

        private fun createCertificate(cnName: String, issuer: Certificate?, isCA: Boolean, alg: String, signAlg: String, keySize: Int): Certificate {
            // Generate the key-pair
            val keyGen = KeyPairGenerator.getInstance(alg)
            keyGen.initialize(keySize)
            val certKeyPair = keyGen.generateKeyPair()
            val subject = X500NameBuilder(BCStyle.INSTANCE)
                .addRDN(BCStyle.CN, cnName)
                .addRDN(BCStyle.O, "Acme")
                .addRDN(BCStyle.C, "FI")
                .build()

            // If there is no issuer, we self-sign our certificate.
            val issuerName: X500Name
            val issuerKey: PrivateKey
            if (issuer == null) {
                issuerName = subject
                issuerKey = certKeyPair.private
            } else {
                issuerName = issuer.x509Cert.subject
                issuerKey = issuer.privateKey
            }

            val builder = JcaX509v3CertificateBuilder(
                issuerName,
                BigInteger.valueOf(System.currentTimeMillis()),
                Date.from(Instant.now()),
                Date.from(Instant.now().plus(Duration.ofHours(1))),
                subject,
                certKeyPair.public
            )

            if (isCA) {
                builder.addExtension(Extension.basicConstraints, true, BasicConstraints(true))
                // builder.addExtension(Extension.keyUsage, true, KeyUsage(0b10000110))
                // builder.addExtension(Extension.subjectKeyIdentifier, false, SubjectKeyIdentifier("Cb0jd1O3DTPNW724qnzEUqG4l2Z6".encodeToByteArray()))
            }

            // sign
            val signer = JcaContentSignerBuilder(signAlg).build(issuerKey)
            return Certificate(certKeyPair.private, builder.build(signer), alg, signAlg, keySize)
        }
    }
}
