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
 * Seals and opens [SessionWithContext.sessionBlob] so that a [SessionStore] can satisfy the
 * confidentiality and integrity properties its contract requires. The blob carries the session
 * master secret and has no authentication tag of its own; an AES-GCM envelope supplies both.
 *
 * A store seals on write and opens on read:
 *
 * ```
 * // write
 * val (sealed, encCtx) = engine.activeEncryptionStrategy().encrypt(session.sessionBlob)
 * // persist `sealed` together with `encCtx.version` and `encCtx.properties`
 *
 * // read
 * val blob = engine.encryptionStrategy(storedEncryptionContext).decrypt(sealed)
 * ```
 *
 * The [EncryptionContext] must be stored alongside the ciphertext: it names the key the blob was
 * sealed with and carries the nonce, so it is what makes key rotation possible. Rotation is by key
 * id — [DtlsSessionEncryptionConfig.aesGcmActiveKeyId] selects the key new sessions are sealed
 * with, while reads follow the key id recorded in each stored context, so a fleet sharing one store
 * can roll forward while old sessions remain readable.
 *
 * Two properties are deliberately left to the caller, because only the caller can enforce them:
 *
 * - **Version pinning.** [encryptionStrategy] honours the version it is given, and
 *   [EncryptionContext.Version.NO_ENCRYPTION] returns the bytes unchanged — that is what allows a
 *   store holding unsealed blobs to be migrated in place. If the stored version is itself
 *   attacker-writable, an attacker can therefore downgrade a row to `NO_ENCRYPTION` and bypass the
 *   tag check entirely. Once migration is complete, a store should require the version it expects
 *   rather than trusting what it read back.
 * - **Binding to the CID.** The envelope authenticates the blob's bytes, not which CID they belong
 *   to, so a store must not let a sealed row be moved between CIDs.
 */
class DtlsSessionEncryptionEngine(private val config: DtlsSessionEncryptionConfig) {
    private val activeEncryptionContext = when (config.activeEncryptionVersion) {
        EncryptionContext.Version.NO_ENCRYPTION -> EncryptionContext(config.activeEncryptionVersion)

        EncryptionContext.Version.AES_GCM -> EncryptionContext(
            config.activeEncryptionVersion,
            mapOf(EncryptionContext.KEY_ID_PROP to config.aesGcmActiveKeyId!!)
        )
    }

    /** Strategy for opening a blob sealed under [ctx], as recorded next to it in the store. */
    fun encryptionStrategy(ctx: EncryptionContext?): EncryptionStrategy = when {
        ctx == null || ctx.version == EncryptionContext.Version.NO_ENCRYPTION -> NoEncryptionStrategy
        ctx.version == EncryptionContext.Version.AES_GCM -> AesEncryptionStrategy(ctx, config.aesGcmKeyStore)
        else -> throw DtlsSessionEncryptionException("Requested encryption type ${ctx.version} is not supported")
    }

    /** Strategy for sealing a new blob, under the configured active version and key. */
    fun activeEncryptionStrategy(): EncryptionStrategy = encryptionStrategy(activeEncryptionContext)
}

/**
 * Which version seals new blobs, and the keys available to open existing ones.
 *
 * [aesGcmKeyStore] maps key id to raw AES key bytes; loading those keys — from files, environment
 * or a secret manager — is the application's concern, not the library's. Keys should be 16, 24 or
 * 32 bytes.
 */
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

/**
 * Names the key a blob was sealed with and carries the nonce. Stored next to the ciphertext, and
 * passed back to [DtlsSessionEncryptionEngine.encryptionStrategy] to open it.
 */
data class EncryptionContext(val version: Version, val properties: Map<String, String> = mapOf()) {
    constructor(version: String?, properties: Map<String, String>?) : this(
        version?.let { Version.valueOf(it) } ?: Version.NO_ENCRYPTION,
        properties ?: mapOf()
    )

    enum class Version {
        /** Blob is stored as-is. Only for migrating a store that already holds unsealed blobs. */
        NO_ENCRYPTION,
        AES_GCM
    }

    companion object {
        const val KEY_ID_PROP = "keyId"
        const val IV_PROP = "iv"
    }

    operator fun get(propKey: String): String? = properties[propKey]
}

// Extends Exception rather than Throwable on purpose: a store rejecting a tampered blob is an
// ordinary failure, and callers guard their read path with `catch (e: Exception)`.
class DtlsSessionEncryptionException(msg: String? = null, cause: Throwable? = null) : Exception(msg, cause)
