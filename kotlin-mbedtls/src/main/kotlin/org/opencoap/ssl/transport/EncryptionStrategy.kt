/*
 * Copyright (c) 2022-2026 kotlin-mbedtls contributors (https://github.com/open-coap/kotlin-mbedtls)
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

import java.security.SecureRandom
import java.util.Base64
import javax.crypto.Cipher
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

sealed interface EncryptionStrategy {
    /** Seals [bytes], returning the ciphertext and the context needed to open it again. */
    fun encrypt(bytes: ByteArray): Pair<ByteArray, EncryptionContext>

    /** Opens [bytes]. Throws [DtlsSessionEncryptionException] if they are not authentic. */
    fun decrypt(bytes: ByteArray): ByteArray
}

/**
 * Passes the blob through untouched, leaving both confidentiality and integrity to the store.
 * Its purpose is migration: a store already holding unsealed blobs can keep reading them while
 * new sessions are written under [EncryptionContext.Version.AES_GCM].
 */
object NoEncryptionStrategy : EncryptionStrategy {
    override fun encrypt(bytes: ByteArray): Pair<ByteArray, EncryptionContext> = Pair(bytes, EncryptionContext(EncryptionContext.Version.NO_ENCRYPTION))

    override fun decrypt(bytes: ByteArray): ByteArray = bytes
}

/**
 * AES-GCM with a 128-bit tag, which gives the blob both confidentiality and integrity: a modified
 * blob fails the tag check and [decrypt] throws instead of returning bytes mbedTLS would load.
 *
 * The nonce is fresh per [encrypt] and recorded in the returned [EncryptionContext] under
 * [EncryptionContext.IV_PROP]. Nonce reuse under one key breaks GCM badly — it leaks the XOR of
 * the plaintexts and permits tag forgery — so it comes from [SecureRandom], never a general
 * purpose RNG.
 */
class AesEncryptionStrategy(private val ctx: EncryptionContext, keyStore: KeyStore) : EncryptionStrategy {
    private val keyId: String = ctx[EncryptionContext.KEY_ID_PROP] ?: throw DtlsSessionEncryptionException("Provided encryption context is missing active key id")
    private val key: SecretKey

    init {
        val keyData = keyStore[keyId] ?: throw DtlsSessionEncryptionException("Key ID $keyId is missing from the key store")
        key = SecretKeySpec(keyData, "AES")
    }

    override fun encrypt(bytes: ByteArray): Pair<ByteArray, EncryptionContext> {
        try {
            val iv = ByteArray(GCM_IV_LENGTH).also(random::nextBytes)
            val cipher = Cipher.getInstance(TRANSFORMATION)
            cipher.init(Cipher.ENCRYPT_MODE, key, GCMParameterSpec(GCM_TAG_LENGTH_BITS, iv))
            val result = cipher.doFinal(bytes)

            val ctx = EncryptionContext(
                EncryptionContext.Version.AES_GCM,
                mapOf(
                    EncryptionContext.KEY_ID_PROP to keyId,
                    EncryptionContext.IV_PROP to Base64.getEncoder().encodeToString(cipher.iv)
                )
            )

            return Pair(result, ctx)
        } catch (e: Throwable) {
            throw DtlsSessionEncryptionException("Failed to encrypt", e)
        }
    }

    override fun decrypt(bytes: ByteArray): ByteArray {
        val iv = ctx[EncryptionContext.IV_PROP]?.let(Base64.getDecoder()::decode) ?: throw DtlsSessionEncryptionException("IV is missing from the context")
        try {
            val cipher = Cipher.getInstance(TRANSFORMATION)
            cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(GCM_TAG_LENGTH_BITS, iv))
            return cipher.doFinal(bytes)
        } catch (e: Throwable) {
            throw DtlsSessionEncryptionException("Failed to decrypt", e)
        }
    }

    companion object {
        const val GCM_TAG_LENGTH_BITS = 128
        const val GCM_IV_LENGTH = 16
        private const val TRANSFORMATION = "AES/GCM/NoPadding"
        private val random = SecureRandom()
    }
}
