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

typealias KeyStore = Map<String, ByteArray>

/**
 * Seals and opens [SessionWithContext.sessionBlob], giving a [SessionStore] the confidentiality and
 * integrity its contract requires. Rotation is by key id: writes use the configured active key,
 * reads follow the key id in each session's stored [EncryptionContext].
 *
 * Two things only the caller can enforce:
 * - [EncryptionContext.Version.NO_ENCRYPTION] returns bytes unchanged, for migrating a store of
 *   unsealed blobs. Taking the version from an attacker-writable field is a downgrade past the tag
 *   check, so pin the version you expect once migrated.
 * - The envelope authenticates the blob's bytes, not which CID they belong to, so a store must not
 *   let a sealed row move between CIDs.
 */
class DtlsSessionEncryptionEngine(private val config: DtlsSessionEncryptionConfig) {
    private val activeEncryptionContext = when (config.activeEncryptionVersion) {
        EncryptionContext.Version.NO_ENCRYPTION -> EncryptionContext(config.activeEncryptionVersion)

        EncryptionContext.Version.AES_GCM -> EncryptionContext(
            config.activeEncryptionVersion,
            mapOf(EncryptionContext.KEY_ID_PROP to config.aesGcmActiveKeyId!!)
        )
    }

    fun encryptionStrategy(ctx: EncryptionContext?): EncryptionStrategy = when {
        ctx == null || ctx.version == EncryptionContext.Version.NO_ENCRYPTION -> NoEncryptionStrategy
        ctx.version == EncryptionContext.Version.AES_GCM -> AesEncryptionStrategy(ctx, config.aesGcmKeyStore)
        else -> throw DtlsSessionEncryptionException("Requested encryption type ${ctx.version} is not supported")
    }

    fun activeEncryptionStrategy(): EncryptionStrategy = encryptionStrategy(activeEncryptionContext)
}

data class DtlsSessionEncryptionConfig(
    val activeEncryptionVersion: EncryptionContext.Version,
    val aesGcmKeyStore: KeyStore = mapOf(),
    val aesGcmActiveKeyId: String? = null
) {
    init {
        require(activeEncryptionVersion != EncryptionContext.Version.AES_GCM || aesGcmActiveKeyId != null) {
            "aesGcmActiveKeyId must be specified when activeEncryptionVersion is AES_GCM"
        }
    }
}

data class EncryptionContext(val version: Version, val properties: Map<String, String> = mapOf()) {
    constructor(version: String?, properties: Map<String, String>?) : this(
        version?.let { Version.valueOf(it) } ?: Version.NO_ENCRYPTION,
        properties ?: mapOf()
    )

    enum class Version {
        NO_ENCRYPTION,
        AES_GCM
    }

    companion object {
        const val KEY_ID_PROP = "keyId"
        const val IV_PROP = "iv"
    }

    operator fun get(propKey: String): String? = properties[propKey]
}

// Exception, not Throwable: callers guard their read path with `catch (e: Exception)`.
class DtlsSessionEncryptionException(msg: String? = null, cause: Throwable? = null) : Exception(msg, cause)
