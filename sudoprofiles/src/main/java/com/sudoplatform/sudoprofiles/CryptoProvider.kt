/*
 * Copyright © 2022 Anonyome Labs, Inc. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package com.sudoplatform.sudoprofiles

import android.content.Context
import android.util.Base64
import com.sudoplatform.sudokeymanager.KeyManagerFactory
import com.sudoplatform.sudokeymanager.KeyManagerInterface
import com.sudoplatform.sudokeymanager.KeyType
import java.io.Serializable
import java.util.Locale
import java.util.UUID

/**
 * Exported encryption key.
 */
data class EncryptionKey(
    /**
     * Key ID.
     */
    val id: String,

    /**
     * Key namespace.
     */
    val namespace: String,

    /**
     * Base64 encoded key.
     */
    val key: String,

    /**
     * Cryptographic algorithm associated with the key.
     */
    val algorithm: String,

    /**
     * Key version.
     */
    val version: Int
) : Serializable

/**
 * Supported symmetric key algorithms.
 */
enum class SymmetricKeyEncryptionAlgorithm(private val stringValue: String) {
    AES_CBC_PKCS7PADDING("AES/CBC/PKCS7Padding");

    companion object {

        fun fromString(stringValue: String): SymmetricKeyEncryptionAlgorithm? {
            var value: SymmetricKeyEncryptionAlgorithm? = null
            if (stringValue == "AES/CBC/PKCS7Padding") {
                value =
                    AES_CBC_PKCS7PADDING
            }

            return value
        }
    }

    override fun toString(): String {
        when (this) {
            AES_CBC_PKCS7PADDING -> return this.stringValue
        }
    }
}

/**
 * Provides utility functions for cryptographic operations.
 */
interface CryptoProvider {
    /**
     * Encrypts the given data using the specified key and encryption algorithm.
     *
     * @param keyId ID of the encryption key to use.
     * @param algorithm encryption algorithm to use.
     * @param data data to encrypt.
     * @return ByteArray: encrypted data.
     */
    fun encrypt(
        keyId: String,
        algorithm: SymmetricKeyEncryptionAlgorithm,
        data: ByteArray
    ): ByteArray

    /**
     * Encrypts the given data using the specified key and encryption algorithm.
     *
     * @param keyId ID of the encryption key to use.
     * @param algorithm encryption algorithm to use.
     * @param data data to decrypt.
     * @return ByteArray: decrypted data.
     */
    fun decrypt(
        keyId: String,
        algorithm: SymmetricKeyEncryptionAlgorithm,
        data: ByteArray
    ): ByteArray

    /**
     * Generate an encryption key to use for encrypting Sudo claims. Any existing keys are not
     * removed to be able to decrypt existing claims but new claims will be encrypted using the
     * newly generated key.
     *
     * @return String: unique ID of the generated key.
     */
    fun generateEncryptionKey(): String

    /**
     * Get the current (most recently generated) symmetric key ID.
     *
     * @return String: symmetric key ID.
     */
    fun getSymmetricKeyId(): String?

    /**
     * Import encryption keys to use for encrypting and decrypting Sudo claims. All existing keys
     * will be removed before the new keys are imported.
     *
     * @param keys keys to import.
     * @param currentKeyId ID of the key to use for encrypting new claims.
     */
    fun importEncryptionKeys(keys: List<EncryptionKey>, currentKeyId: String)

    /**
     * Export encryption keys used for encrypting and decrypting Sudo claims.
     *
     * @return List<EncryptionKey>: Encryption keys.
     */
    fun exportEncryptionKeys(): List<EncryptionKey>

    /**
     * Removes all keys associated with this provider.
     */
    fun reset()
}

/**
 * Default [CryptoProvider] implementation.
 */
class DefaultCryptoProvider(private val keyNamespace: String, private val databaseName: String, context: Context) : CryptoProvider {

    companion object {
        private const val KEY_NAME_SYMMETRIC_KEY_ID = "symmetricKeyId"
        private const val AES_BLOCK_SIZE = 16
    }

    private val keyManager: KeyManagerInterface =
        KeyManagerFactory(context).createAndroidKeyManager(this.keyNamespace, this.databaseName)

    override fun encrypt(
        keyId: String,
        algorithm: SymmetricKeyEncryptionAlgorithm,
        data: ByteArray
    ): ByteArray {
        val iv = this.keyManager.createRandomData(AES_BLOCK_SIZE)
        val encryptedData = this.keyManager.encryptWithSymmetricKey(
            keyId,
            data,
            iv,
            KeyManagerInterface.SymmetricEncryptionAlgorithm.AES_CBC_PKCS7_256
        )

        return encryptedData + iv
    }

    override fun decrypt(
        keyId: String,
        algorithm: SymmetricKeyEncryptionAlgorithm,
        data: ByteArray
    ): ByteArray {
        val encryptedData = data.copyOfRange(0, data.count() - AES_BLOCK_SIZE)
        val iv = data.copyOfRange(data.count() - AES_BLOCK_SIZE, data.count())

        return this.keyManager.decryptWithSymmetricKey(
            keyId,
            encryptedData,
            iv,
            KeyManagerInterface.SymmetricEncryptionAlgorithm.AES_CBC_PKCS7_256
        )
    }

    override fun generateEncryptionKey(): String {
        // Delete existing key.
        val symmetricKeyId = this.getSymmetricKeyId()
        if (symmetricKeyId != null) {
            this.keyManager.deleteSymmetricKey(symmetricKeyId)
            this.keyManager.deletePassword(KEY_NAME_SYMMETRIC_KEY_ID)
        }

        // Generate and store symmetric key ID.
        val keyId = UUID.randomUUID().toString().uppercase(Locale.US)
        this.keyManager.addPassword(keyId.toByteArray(), KEY_NAME_SYMMETRIC_KEY_ID)

        // Generate symmetric key for encrypting secrets.
        this.keyManager.generateSymmetricKey(keyId)

        return keyId
    }

    override fun getSymmetricKeyId(): String? {
        return this.keyManager.getPassword(KEY_NAME_SYMMETRIC_KEY_ID)
            ?.toString(Charsets.UTF_8)
    }

    override fun importEncryptionKeys(keys: List<EncryptionKey>, currentKeyId: String) {
        this.keyManager.removeAllKeys()

        for (key in keys) {
            this.keyManager.addSymmetricKey(Base64.decode(key.key, Base64.DEFAULT), key.id)
        }

        this.keyManager.addPassword(currentKeyId.toByteArray(), KEY_NAME_SYMMETRIC_KEY_ID)
    }

    override fun exportEncryptionKeys(): List<EncryptionKey> {
        val keys = this.keyManager.exportKeys().filter { key -> key.keyType == KeyType.SYMMETRIC_KEY }
        return keys.map { key ->
            EncryptionKey(
                key.name.removePrefix(this.keyNamespace + "."),
                this.keyNamespace,
                Base64.encodeToString(key.key, Base64.NO_WRAP),
                SymmetricKeyEncryptionAlgorithm.AES_CBC_PKCS7PADDING.toString(),
                1
            )
        }
    }

    override fun reset() {
        this.keyManager.removeAllKeys()
    }
}
