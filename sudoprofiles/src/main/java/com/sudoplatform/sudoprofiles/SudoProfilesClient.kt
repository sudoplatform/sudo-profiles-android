/*
 * Copyright © 2024 Anonyome Labs, Inc. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package com.sudoplatform.sudoprofiles

import android.content.Context
import android.net.Uri
import android.util.Base64
import androidx.core.net.toFile
import com.apollographql.apollo3.api.Optional
import com.sudoplatform.sudoapiclient.ApiClientManager
import com.sudoplatform.sudoconfigmanager.DefaultSudoConfigManager
import com.sudoplatform.sudokeymanager.AndroidSQLiteStore
import com.sudoplatform.sudologging.Logger
import com.sudoplatform.sudoprofiles.exceptions.SudoProfileException
import com.sudoplatform.sudoprofiles.exceptions.SudoProfileException.Companion.toSudoProfileException
import com.sudoplatform.sudoprofiles.graphql.CreateSudoMutation
import com.sudoplatform.sudoprofiles.graphql.DeleteSudoMutation
import com.sudoplatform.sudoprofiles.graphql.GetOwnershipProofMutation
import com.sudoplatform.sudoprofiles.graphql.ListSudosQuery
import com.sudoplatform.sudoprofiles.graphql.OnCreateSudoSubscription
import com.sudoplatform.sudoprofiles.graphql.OnDeleteSudoSubscription
import com.sudoplatform.sudoprofiles.graphql.OnUpdateSudoSubscription
import com.sudoplatform.sudoprofiles.graphql.UpdateSudoMutation
import com.sudoplatform.sudoprofiles.graphql.type.CreateSudoInput
import com.sudoplatform.sudoprofiles.graphql.type.DeleteSudoInput
import com.sudoplatform.sudoprofiles.graphql.type.GetOwnershipProofInput
import com.sudoplatform.sudoprofiles.graphql.type.SecureClaimInput
import com.sudoplatform.sudoprofiles.graphql.type.SecureS3ObjectInput
import com.sudoplatform.sudoprofiles.graphql.type.UpdateSudoInput
import com.sudoplatform.sudouser.SudoUserClient
import com.sudoplatform.sudouser.amplify.GraphQLClient
import kotlinx.coroutines.Dispatchers.IO
import kotlinx.coroutines.GlobalScope
import kotlinx.coroutines.launch
import org.json.JSONObject
import java.util.Date

/**
 * Options for controlling the behaviour of `listSudos` API.
 */
enum class ListOption {
    /**
     * Returns Sudos from the local cache only.
     */
    CACHE_ONLY,

    /**
     * Fetches Sudos from the backend and ignores any cached entries.
     */
    REMOTE_ONLY,

    /**
     * Returns Sudos from the local cache if cache is not empty otherwise fetch from the backend.
     */
    RETURN_CACHED_ELSE_FETCH,
}

/**
 * Interface encapsulating a library of functions for calling Sudo service and managing Sudos.
 */
interface SudoProfilesClient {

    companion object {
        private const val CONFIG_NAMESPACE_IDENTITY_SERVICE = "identityService"
        private const val CONFIG_NAMESPACE_SUDO_SERVICE = "sudoService"
        private const val CONFIG_REGION = "region"
        private const val CONFIG_BUCKET = "bucket"

        /**
         * Creates a [Builder] for [SudoProfilesClient].
         */
        fun builder(
            context: Context,
            sudoUserClient: SudoUserClient,
            blobContainerURI: Uri,
        ) =
            Builder(
                context,
                sudoUserClient,
                blobContainerURI,
            )
    }

    /**
     * Builder used to construct [SudoProfilesClient].
     */
    class Builder(
        private val context: Context,
        private val sudoUserClient: SudoUserClient,
        private val blobContainerURI: Uri,
    ) {
        private var logger: Logger = DefaultLogger.instance
        private var config: JSONObject? = null
        private var maxSudos: Int = 10
        private var graphQLClient: GraphQLClient? = null
        private var s3Client: S3Client? = null
        private var idGenerator: IdGenerator = DefaultIdGenerator()
        private var cryptoProvider: CryptoProvider? = null
        private var namespace: String? = DEFAULT_KEY_NAMESPACE
        private var databaseName: String? = AndroidSQLiteStore.DEFAULT_DATABASE_NAME

        companion object {
            private const val DEFAULT_KEY_NAMESPACE = "ss"
        }

        /**
         * Provide the implementation of the [Logger] used for logging. If a value is not supplied
         * a default implementation will be used.
         */
        fun setLogger(logger: Logger) = also { this.logger = logger }

        /**
         * Provide the Configuration Parameters
         */
        fun setConfig(config: JSONObject) = also { this.config = config }

        /**
         * Provide the namespace to use for internal data and cryptographic keys. This should be unique
         * per client per app to avoid name conflicts between multiple clients. If a value is not supplied
         * a default value will be used.
         */
        fun setNamespace(namespace: String) = also {
            this.namespace = namespace
        }

        /**
         * Provide the database name to use for exportable key store database.
         */
        fun setDatabaseName(databaseName: String) = also {
            this.databaseName = databaseName
        }

        /**
         * Provide the maximum number of Sudos to cap the queries to.  If a value is not supplied
         * a default of 10 will be set.
         */
        fun setMaxSudos(maxSudos: Int) = also { this.maxSudos = maxSudos }

        /**
         * Provide an [GraphQLClient] for the [GraphQLClient]. If this is not
         * supplied, an [GraphQLClient] will be obtained from [ApiClientManager].
         */
        fun setGraphQLClient(graphQLClient: GraphQLClient) = also { this.graphQLClient = graphQLClient }

        /**
         * Provide an [S3Client] to use for AWS S3 related operations.  If a value is not supplied
         * a default implementation will be used.
         */
        fun setS3Client(s3Client: S3Client) = also { this.s3Client = s3Client }

        /**
         * Provide an [IdGenerator] to use.  If a value is not supplied
         * a default implementation will be provided.
         */
        fun setIdGenerator(idGenerator: IdGenerator) = also { this.idGenerator = idGenerator }

        /**
         * Provide a [CryptoProvider] to use.  If a value is not supplied
         * a default implementation will be provided.
         */
        fun setCryptoProvider(cryptoProvider: CryptoProvider) = also { this.cryptoProvider = cryptoProvider }

        /**
         * Constructs and returns an [SudoProfilesClient].
         */
        fun build(): SudoProfilesClient {
            val graphQLClient = this.graphQLClient
                ?: ApiClientManager.getClient(
                    this.context,
                    this.sudoUserClient,
                )

            val configManager = DefaultSudoConfigManager(this.context, this.logger)

            @Suppress("UNCHECKED_CAST")
            val identityServiceConfig =
                this.config?.opt(CONFIG_NAMESPACE_IDENTITY_SERVICE) as JSONObject?
                    ?: configManager.getConfigSet(CONFIG_NAMESPACE_IDENTITY_SERVICE)
                    ?: throw SudoProfileException.InvalidConfigException()

            val sudoServiceConfig =
                config?.opt(CONFIG_NAMESPACE_SUDO_SERVICE) as JSONObject?
                    ?: configManager.getConfigSet(CONFIG_NAMESPACE_SUDO_SERVICE)
                    ?: throw SudoProfileException.SudoServiceConfigNotFoundException()

            val bucket =
                sudoServiceConfig.opt(CONFIG_BUCKET) as String? ?: identityServiceConfig.opt(
                    CONFIG_BUCKET,
                ) as String?
                    ?: throw SudoProfileException.InvalidConfigException("Bucket name missing.")
            val region =
                sudoServiceConfig.opt(CONFIG_REGION) as String? ?: identityServiceConfig.opt(
                    CONFIG_REGION,
                ) as String?
                    ?: throw SudoProfileException.InvalidConfigException("Region missing.")

            return DefaultSudoProfilesClient(
                this.context,
                this.sudoUserClient,
                this.blobContainerURI,
                this.logger,
                this.config,
                this.maxSudos,
                graphQLClient,
                this.s3Client
                    ?: DefaultS3Client(this.context, this.sudoUserClient, region, bucket),
                this.idGenerator,
                this.cryptoProvider,
                this.namespace ?: DEFAULT_KEY_NAMESPACE,
                this.databaseName ?: AndroidSQLiteStore.DEFAULT_DATABASE_NAME,
            )
        }
    }

    /**
     * Client version.
     */
    val version: String

    /**
     * Creates a new Sudo
     *
     * @param sudo Sudo to create.
     * @return Sudo: The new Sudo
     */
    @Throws(SudoProfileException::class)
    suspend fun createSudo(sudo: Sudo): Sudo

    /**
     * Updates a Sudo.
     *
     * @param sudo Sudo to update.
     * @return Sudo: The updated Sudo
     */
    @Throws(SudoProfileException::class)
    suspend fun updateSudo(sudo: Sudo): Sudo

    /**
     * Deletes a Sudo.
     *
     * @param sudo Sudo to delete.
     * @return void
     */
    @Throws(SudoProfileException::class)
    suspend fun deleteSudo(sudo: Sudo)

    /**
     * Retrieves all Sudos owned by the signed in user.
     *
     * @param option: option for controlling the behaviour of this API. Refer to `ListOption` enum.
     * @return List<Sudo>: A list of Sudos
     */
    @Throws(SudoProfileException::class)
    suspend fun listSudos(option: ListOption): List<Sudo>

    /**
     * Reset any internal state and cached content.
     */
    fun reset()

    /**
     * Retrieves a signed ownership proof for the specified owner. The ownership proof JWT has the
     * following payload.
     * {
     *  "jti": "DBEEF4EB-F84A-4AB7-A45E-02B05B93F5A3",
     *  "owner": "cd73a478-23bd-4c70-8c2b-1403e2085845",
     *  "iss": "sudoplatform.sudoservice",
     *  "aud": "sudoplatform.virtualcardservice",
     *  "exp": 1578986266,
     *  "sub": "da17f346-cf49-4db4-98c2-862f85515fc4",
     *  "iat": 1578982666
     *  }
     *
     *  "owner" is an unique ID of an identity managed by the issuing serivce. In case of Sudo
     *  service this represents unique reference to a Sudo. "sub" is the subject to which this
     *  proof is issued, i.e. the user. "aud" is the target audience of the proof.
     *
     *  @param sudo Sudo to generated an ownership proof for.
     *  @param audience target audience for this proof.
     *  @return String: The JWT
     */
    @Throws(SudoProfileException::class)
    suspend fun getOwnershipProof(sudo: Sudo, audience: String): String

    /**
     * Subscribes to be notified of new, updated or deleted Sudos. Blob data is not downloaded automatically
     * so the caller is expected to use `listSudos` API if they need to access any associated blobs.
     *
     * @param id unique ID for the subscriber.
     * @param changeType change type to subscribe to.
     * @param subscriber subscriber to notify.
     */
    suspend fun subscribeAsync(id: String, changeType: SudoSubscriber.ChangeType, subscriber: SudoSubscriber)

    /**
     * Subscribes to be notified of new, updated and deleted Sudos. Blob data is not downloaded automatically
     * so the caller is expected to use `listSudos` API if they need to access any associated blobs.
     *
     * @param id unique ID for the subscriber.
     * @param subscriber subscriber to notify.
     */
    suspend fun subscribeAsync(id: String, subscriber: SudoSubscriber)

    /**
     * Unsubscribes the specified subscriber so that it no longer receives notifications about
     * new, updated or deleted Sudos.
     *
     * @param id unique ID for the subscriber.
     * @param changeType change type to unsubscribe from.
     */
    fun unsubscribe(id: String, changeType: SudoSubscriber.ChangeType)

    /**
     * Unsubscribes the specified subscriber so that it no longer receives change notifications.
     *
     * @param id unique ID for the subscriber.
     */
    fun unsubscribe(id: String)

    /**
     * Unsubscribe all subscribers from receiving notifications about new, updated or deleted Sudos.
     */
    fun unsubscribeAll()

    /**
     * Generate an encryption key to use for encrypting Sudo claims. Any existing keys are not removed
     * to be able to decrypt existing claims but new claims will be encrypted using the newly generated
     * key.
     *
     * @return String: unique ID of the generated key.
     */
    fun generateEncryptionKey(): String

    /**
     * Get the current (most recently generated) symmetric key ID used for encryption.
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
}

/**
 * Default implementation of [SudoProfilesClient] interface.
 *
 * @param context Android app context.
 * @param sudoUserClient `SudoUserClient` instance required to issue authentication tokens and perform cryptographic operations.
 * @param blobContainerURI container URI to which large binary objects will be stored.
 * @param logger logger used for logging messages.
 * @param config configuration parameters.
 * @param maxSudos maximum number of Sudos to cap the queries to. Defaults to 10.
 * @param graphQLClient optional GraphQL client to use. Mainly used for unit testing.
 * @param s3Client optional S3 client to use. Mainly used for unit testing.
 * @param idGenerator optional GUID generator to use. Mainly used for unit testing.
 * @param namespace namespace to use for internal data and cryptographic keys. This should be unique
 * @param databaseName database name to use for the exportable key store database.
 */
class DefaultSudoProfilesClient(
    private val context: Context,
    private val sudoUserClient: SudoUserClient,
    blobContainerURI: Uri,
    private val logger: Logger = DefaultLogger.instance,
    config: JSONObject? = null,
    maxSudos: Int = 10,
    graphQLClient: GraphQLClient? = null,
    s3Client: S3Client? = null,
    idGenerator: IdGenerator = DefaultIdGenerator(),
    cryptoProvider: CryptoProvider? = null,
    private val namespace: String = DEFAULT_KEY_NAMESPACE,
    private val databaseName: String = AndroidSQLiteStore.DEFAULT_DATABASE_NAME,
) : SudoProfilesClient {

    companion object {
        private const val CONFIG_NAMESPACE_SUDO_SERVICE = "sudoService"
        private const val CONFIG_REGION = "region"
        private const val CONFIG_BUCKET = "bucket"

        private const val DEFAULT_KEY_NAMESPACE = "ss"
    }

    override val version: String = "16.0.0"

    /**
     * GraphQL client used for calling Sudo service API.
     */
    private val graphQLClient: GraphQLClient

    /**
     * UUID generator.
     */
    private val idGenerator: IdGenerator

    /**
     * S3 client to use for AWS S3 related operations.
     */
    private val s3Client: S3Client

    /**
     * Cache for storing large binary objects.
     */
    private val blobCache: BlobCache

    /**
     * Default query for fetching Sudos.
     */
    private val defaultQueryInput: Map<String, Any?>

    /**
     * [CryptoProvider] to use for cryptographic operations.
     */
    private val cryptoProvider: CryptoProvider

    /**
     * Subscription manager for Sudo creation events.
     */
    private val onCreateSudoSubscriptionManager: SubscriptionManager<OnCreateSudoSubscription.Data>

    /**
     * Subscription manager for Sudo update events.
     */
    private val onUpdateSudoSubscriptionManager: SubscriptionManager<OnUpdateSudoSubscription.Data>

    /**
     * Subscription manager for Sudo deletion events.
     */
    private val onDeleteSudoSubscriptionManager: SubscriptionManager<OnDeleteSudoSubscription.Data>

    init {
        val sudoServiceConfig =
            config?.opt(CONFIG_NAMESPACE_SUDO_SERVICE) as JSONObject?
                ?: DefaultSudoConfigManager(context, this.logger).getConfigSet(CONFIG_NAMESPACE_SUDO_SERVICE)
                ?: throw SudoProfileException.SudoServiceConfigNotFoundException()

        val bucket =
            sudoServiceConfig.opt(CONFIG_BUCKET) as String? ?: throw SudoProfileException.InvalidConfigException("Bucket name missing.")
        val region = sudoServiceConfig.opt(CONFIG_REGION) as String? ?: throw SudoProfileException.InvalidConfigException("Region missing.")

        this.graphQLClient = graphQLClient
            ?: ApiClientManager.getClient(
                context,
                this.sudoUserClient,
            )

        this.s3Client =
            s3Client ?: DefaultS3Client(this.context, this.sudoUserClient, region, bucket)

        this.cryptoProvider = cryptoProvider ?: DefaultCryptoProvider(this.namespace, this.databaseName, context)

        if (this.cryptoProvider.getSymmetricKeyId() == null) {
            this.cryptoProvider.generateEncryptionKey()
        }

        this.idGenerator = idGenerator

        this.blobCache = BlobCache(blobContainerURI, this.idGenerator)

        this.defaultQueryInput = mapOf(
            "limit" to Optional.presentIfNotNull(maxSudos),
            "nextToken" to Optional.presentIfNotNull(null),
        )

        this.onCreateSudoSubscriptionManager = SubscriptionManager()
        this.onUpdateSudoSubscriptionManager = SubscriptionManager()
        this.onDeleteSudoSubscriptionManager = SubscriptionManager()
    }

    override suspend fun createSudo(sudo: Sudo): Sudo {
        this.logger.info("Creating a Sudo.")

        val keyId = this.cryptoProvider.getSymmetricKeyId()
        require(keyId != null) { "Symmetric key missing." }
        val input = CreateSudoInput(claims = emptyList(), objects = emptyList())

        try {
            val response = this.graphQLClient.mutate<CreateSudoMutation, CreateSudoMutation.Data>(
                CreateSudoMutation.OPERATION_DOCUMENT,
                mapOf("input" to input),
            )

            if (response.hasErrors()) {
                throw response.errors.first().toSudoProfileException()
            }

            val result = response.data?.createSudo
            if (result != null) {
                sudo.id = result.id
                sudo.version = result.version
                sudo.createdAt = Date(result.createdAtEpochMs.toLong())
                sudo.updatedAt = Date(result.updatedAtEpochMs.toLong())

                return updateSudo(sudo)
            } else {
                throw SudoProfileException.FailedException("Mutation succeeded but output was null.")
            }
        } catch (e: Exception) {
            throw e.toFailedExceptionOrThrow()
        }
    }

    override suspend fun updateSudo(sudo: Sudo): Sudo {
        this.logger.info("Updating a Sudo.")

        val sudoId = sudo.id
        require(sudoId != null) { "Sudo ID was null." }

        val keyId = this.cryptoProvider.getSymmetricKeyId()
        require(keyId != null) { "Symmetric key missing." }

        try {
            val secureClaims: MutableList<SecureClaimInput> = mutableListOf()
            val secureS3Objects: MutableList<SecureS3ObjectInput> = mutableListOf()

            for ((name, claim) in sudo.claims) {
                if (claim.visibility === Claim.Visibility.PRIVATE) {
                    when (claim.value) {
                        is Claim.Value.BlobValue -> {
                            val file = claim.value.value.normalizeScheme().toFile()
                            val data = file.readBytes()

                            val cacheEntry =
                                this.blobCache.replace(
                                    data,
                                    "sudo/$sudoId/${claim.name}",
                                )

                            try {
                                sudo.claims[name] = Claim(
                                    name,
                                    claim.visibility,
                                    Claim.Value.BlobValue(cacheEntry.toUri()),
                                )

                                val algorithm =
                                    SymmetricKeyEncryptionAlgorithm.AES_CBC_PKCS7PADDING
                                val encrypted =
                                    this.cryptoProvider.encrypt(
                                        keyId,
                                        algorithm,
                                        data,
                                    )

                                val key = this.s3Client.upload(
                                    encrypted,
                                    cacheEntry.id,
                                )

                                secureS3Objects.add(
                                    SecureS3ObjectInput(
                                        name = name,
                                        version = 1,
                                        algorithm = algorithm.toString(),
                                        keyId = keyId,
                                        bucket = this.s3Client.bucket,
                                        region = this.s3Client.region,
                                        key = key,
                                    ),

                                )
                            } catch (e: Exception) {
                                this.blobCache.remove(cacheEntry.id)
                                throw e
                            }
                        }
                        is Claim.Value.StringValue -> {
                            secureClaims.add(
                                this.createSecureString(
                                    name,
                                    claim.value.value,
                                ),
                            )
                        }
                    }
                }
            }

            val input = UpdateSudoInput(
                id = sudoId,
                claims = Optional.presentIfNotNull(secureClaims),
                objects = Optional.presentIfNotNull(secureS3Objects),
                expectedVersion = sudo.version,
            )

            val response = this.graphQLClient.mutate<UpdateSudoMutation, UpdateSudoMutation.Data>(
                UpdateSudoMutation.OPERATION_DOCUMENT,
                mapOf("input" to input),
            )
            if (response.hasErrors()) {
                throw response.errors.first().toSudoProfileException()
            }

            val output = response.data?.updateSudo
            if (output != null) {
                sudo.id = output.id
                sudo.version = output.version
                sudo.createdAt = Date(output.createdAtEpochMs.toLong())
                sudo.updatedAt = Date(output.updatedAtEpochMs.toLong())

                return sudo
            } else {
                throw SudoProfileException.FailedException("Mutation succeeded but output was null.")
            }
        } catch (e: Exception) {
            throw e.toFailedExceptionOrThrow()
        }
    }

    override suspend fun deleteSudo(sudo: Sudo) {
        this.logger.info("Deleting a Sudo.")

        val sudoId = sudo.id
        require(sudoId != null) { "Sudo ID was null." }

        try {
            this.deleteSecureS3Objects(sudoId)

            val input = DeleteSudoInput(
                id = sudoId,
                expectedVersion = sudo.version,
            )

            val response = this.graphQLClient.mutate<DeleteSudoMutation, DeleteSudoMutation.Data>(
                DeleteSudoMutation.OPERATION_DOCUMENT,
                mapOf("input" to input),
            )

            if (response.hasErrors()) {
                throw response.errors.first().toSudoProfileException()
            }
        } catch (e: Exception) {
            throw e.toFailedExceptionOrThrow()
        }
    }

    override suspend fun listSudos(option: ListOption): List<Sudo> {
        this.logger.info("Listing Sudos.")

        try {
            val response = this.graphQLClient.query<ListSudosQuery, ListSudosQuery.Data>(
                ListSudosQuery.OPERATION_DOCUMENT,
                this.defaultQueryInput,
            )

            if (response.hasErrors()) {
                throw response.errors.first().toSudoProfileException()
            }

            var sudos: List<Sudo> = listOf()

            // Iterate over Sudos.
            val items = response.data?.listSudos?.items
            if (items != null) {
                sudos = this.processListSudos(
                    items,
                    option,
                    true,
                )
            }

            return sudos
        } catch (e: Exception) {
            throw e.toFailedExceptionOrThrow()
        }
    }

    override fun reset() {
        this.logger.info("Resetting client.")

        this.blobCache.reset()
        this.cryptoProvider.reset()
    }

    override suspend fun getOwnershipProof(sudo: Sudo, audience: String): String {
        this.logger.info("Getting a Sudo ownership proof.")

        val sudoId = sudo.id
        require(sudoId != null) { "Sudo ID was null." }

        try {
            val input = GetOwnershipProofInput(
                sudoId = sudoId,
                audience = audience,
            )

            val response = this.graphQLClient.mutate<GetOwnershipProofMutation, GetOwnershipProofMutation.Data>(
                GetOwnershipProofMutation.OPERATION_DOCUMENT,
                mapOf("input" to input),
            )

            if (response.hasErrors()) {
                throw response.errors.first().toSudoProfileException()
            }

            val output = response.data?.getOwnershipProof
            if (output != null) {
                return output.jwt
            } else {
                throw SudoProfileException.FailedException("Mutation succeeded but output was null.")
            }
        } catch (e: Exception) {
            throw e.toFailedExceptionOrThrow()
        }
    }

    override suspend fun subscribeAsync(id: String, subscriber: SudoSubscriber) {
        this.subscribeAsync(id, SudoSubscriber.ChangeType.CREATE, subscriber)
        this.subscribeAsync(id, SudoSubscriber.ChangeType.UPDATE, subscriber)
        this.subscribeAsync(id, SudoSubscriber.ChangeType.DELETE, subscriber)
    }

    override suspend fun subscribeAsync(
        id: String,
        changeType: SudoSubscriber.ChangeType,
        subscriber: SudoSubscriber,
    ) {
        this.logger.info("Subscribing for Sudo change notification.")

        val owner = this.sudoUserClient.getSubject()
        require(
            owner != null,
        ) { "Owner was null. The client may not be signed in." }

        when (changeType) {
            SudoSubscriber.ChangeType.CREATE -> {
                this.onCreateSudoSubscriptionManager.replaceSubscriber(id, subscriber)
                if (this.onCreateSudoSubscriptionManager.watcher == null) {
                    this.onCreateSudoSubscriptionManager.watcher =
                        this.graphQLClient.subscribe<OnCreateSudoSubscription, OnCreateSudoSubscription.Data>(
                            OnCreateSudoSubscription.OPERATION_DOCUMENT,
                            mapOf("owner" to owner),
                            {
                                this@DefaultSudoProfilesClient.onCreateSudoSubscriptionManager.connectionStatusChanged(
                                    SudoSubscriber.ConnectionState.CONNECTED,
                                )
                            },
                            {
                                GlobalScope.launch(IO) {
                                    try {
                                        val error = it.errors.firstOrNull()
                                        if (error != null) {
                                            this@DefaultSudoProfilesClient.logger.error("Subscription response contained error: $error")
                                        } else {
                                            val item = it.data?.onCreateSudo
                                            if (item != null) {
                                                val listSudosQueryItem = ListSudosQuery.Item(
                                                    item.id,
                                                    item.claims.map {
                                                        ListSudosQuery.Claim(
                                                            it.name,
                                                            it.version,
                                                            it.algorithm,
                                                            it.keyId,
                                                            it.base64Data,
                                                        )
                                                    },
                                                    item.objects.map {
                                                        ListSudosQuery.Object(
                                                            it.name,
                                                            it.version,
                                                            it.algorithm,
                                                            it.keyId,
                                                            it.bucket,
                                                            it.region,
                                                            it.key,
                                                        )
                                                    },
                                                    item.metadata.map {
                                                        ListSudosQuery.Metadatum(
                                                            it.name,
                                                            it.value,
                                                        )
                                                    },
                                                    item.createdAtEpochMs,
                                                    item.updatedAtEpochMs,
                                                    item.version,
                                                    item.owner,
                                                )

                                                val sudos =
                                                    this@DefaultSudoProfilesClient.processListSudos(
                                                        listOf(listSudosQueryItem),
                                                        ListOption.CACHE_ONLY,
                                                        false,
                                                    )

                                                val sudo = sudos.firstOrNull()
                                                if (sudo != null) {
                                                    this@DefaultSudoProfilesClient.onCreateSudoSubscriptionManager.sudoChanged(
                                                        SudoSubscriber.ChangeType.CREATE,
                                                        sudo,
                                                    )
                                                }
                                            }
                                        }
                                    } catch (e: Exception) {
                                        this@DefaultSudoProfilesClient.logger.error("Failed to process the subscription response: $e")
                                    }
                                }
                            },
                            {
                                // Subscription was terminated. Notify the subscribers.
                                this@DefaultSudoProfilesClient.onCreateSudoSubscriptionManager.connectionStatusChanged(
                                    SudoSubscriber.ConnectionState.DISCONNECTED,
                                )
                            },
                            {
                                // Failed create a subscription. Notify the subscribers.
                                this@DefaultSudoProfilesClient.onCreateSudoSubscriptionManager.connectionStatusChanged(
                                    SudoSubscriber.ConnectionState.DISCONNECTED,
                                )
                            },

                        )
                }
            }
            SudoSubscriber.ChangeType.DELETE -> {
                this.onDeleteSudoSubscriptionManager.replaceSubscriber(id, subscriber)
                this.onDeleteSudoSubscriptionManager.watcher =
                    this.graphQLClient.subscribe<OnDeleteSudoSubscription, OnDeleteSudoSubscription.Data>(
                        OnDeleteSudoSubscription.OPERATION_DOCUMENT,
                        mapOf("owner" to owner),
                        {
                            this@DefaultSudoProfilesClient.onDeleteSudoSubscriptionManager.connectionStatusChanged(
                                SudoSubscriber.ConnectionState.CONNECTED,
                            )
                        },
                        {
                            GlobalScope.launch(IO) {
                                try {
                                    val response = it
                                    val error = response.errors.firstOrNull()
                                    if (error != null) {
                                        this@DefaultSudoProfilesClient.logger.error("Subscription response contained error: $error")
                                    } else {
                                        val item = response.data?.onDeleteSudo
                                        if (item != null) {
                                            val listSudosQueryItem = ListSudosQuery.Item(
                                                item.id,
                                                item.claims.map {
                                                    ListSudosQuery.Claim(
                                                        it.name,
                                                        it.version,
                                                        it.algorithm,
                                                        it.keyId,
                                                        it.base64Data,
                                                    )
                                                },
                                                item.objects.map {
                                                    ListSudosQuery.Object(
                                                        it.name,
                                                        it.version,
                                                        it.algorithm,
                                                        it.keyId,
                                                        it.bucket,
                                                        it.region,
                                                        it.key,
                                                    )
                                                },
                                                item.metadata.map {
                                                    ListSudosQuery.Metadatum(
                                                        it.name,
                                                        it.value,
                                                    )
                                                },
                                                item.createdAtEpochMs,
                                                item.updatedAtEpochMs,
                                                item.version,
                                                item.owner,
                                            )

                                            val sudos =
                                                this@DefaultSudoProfilesClient.processListSudos(
                                                    listOf(listSudosQueryItem),
                                                    ListOption.CACHE_ONLY,
                                                    false,
                                                )

                                            val sudo = sudos.firstOrNull()
                                            if (sudo != null) {
                                                this@DefaultSudoProfilesClient.onDeleteSudoSubscriptionManager.sudoChanged(
                                                    SudoSubscriber.ChangeType.DELETE,
                                                    sudo,
                                                )
                                            }
                                        }
                                    }
                                } catch (e: Exception) {
                                    this@DefaultSudoProfilesClient.logger.error("Failed to process the subscription response: $e")
                                }
                            }
                        },
                        {
                            // Subscription was terminated. Notify the subscribers.
                            this@DefaultSudoProfilesClient.onUpdateSudoSubscriptionManager.connectionStatusChanged(
                                SudoSubscriber.ConnectionState.DISCONNECTED,
                            )
                        },
                        {
                            // Failed create a subscription. Notify the subscribers.
                            this@DefaultSudoProfilesClient.onUpdateSudoSubscriptionManager.connectionStatusChanged(
                                SudoSubscriber.ConnectionState.DISCONNECTED,
                            )
                        },
                    )
            }
            SudoSubscriber.ChangeType.UPDATE -> {
                this.onUpdateSudoSubscriptionManager.replaceSubscriber(id, subscriber)
                this.onUpdateSudoSubscriptionManager.watcher =
                    this.graphQLClient.subscribe<OnUpdateSudoSubscription, OnUpdateSudoSubscription.Data>(
                        OnUpdateSudoSubscription.OPERATION_DOCUMENT,
                        mapOf("owner" to owner),
                        {
                            this@DefaultSudoProfilesClient.onUpdateSudoSubscriptionManager.connectionStatusChanged(
                                SudoSubscriber.ConnectionState.CONNECTED,
                            )
                        },
                        {
                            GlobalScope.launch(IO) {
                                try {
                                    val response = it
                                    val error = response.errors.firstOrNull()
                                    if (error != null) {
                                        this@DefaultSudoProfilesClient.logger.error("Subscription response contained error: $error")
                                    } else {
                                        val item = response.data?.onUpdateSudo
                                        if (item != null) {
                                            val listSudosQueryItem = ListSudosQuery.Item(
                                                item.id,
                                                item.claims.map {
                                                    ListSudosQuery.Claim(
                                                        it.name,
                                                        it.version,
                                                        it.algorithm,
                                                        it.keyId,
                                                        it.base64Data,
                                                    )
                                                },
                                                item.objects.map {
                                                    ListSudosQuery.Object(
                                                        it.name,
                                                        it.version,
                                                        it.algorithm,
                                                        it.keyId,
                                                        it.bucket,
                                                        it.region,
                                                        it.key,
                                                    )
                                                },
                                                item.metadata.map {
                                                    ListSudosQuery.Metadatum(
                                                        it.name,
                                                        it.value,
                                                    )
                                                },
                                                item.createdAtEpochMs,
                                                item.updatedAtEpochMs,
                                                item.version,
                                                item.owner,
                                            )

                                            val sudos =
                                                this@DefaultSudoProfilesClient.processListSudos(
                                                    listOf(listSudosQueryItem),
                                                    ListOption.CACHE_ONLY,
                                                    false,
                                                )

                                            val sudo = sudos.firstOrNull()
                                            if (sudo != null) {
                                                this@DefaultSudoProfilesClient.onUpdateSudoSubscriptionManager.sudoChanged(
                                                    SudoSubscriber.ChangeType.UPDATE,
                                                    sudo,
                                                )
                                            }
                                        }
                                    }
                                } catch (e: Exception) {
                                    this@DefaultSudoProfilesClient.logger.error("Failed to process the subscription response: $e")
                                }
                            }
                        },
                        {
                            // Subscription was terminated. Notify the subscribers.
                            this@DefaultSudoProfilesClient.onUpdateSudoSubscriptionManager.connectionStatusChanged(
                                SudoSubscriber.ConnectionState.DISCONNECTED,
                            )
                        },
                        {
                            // Failed create a subscription. Notify the subscribers.
                            this@DefaultSudoProfilesClient.onUpdateSudoSubscriptionManager.connectionStatusChanged(
                                SudoSubscriber.ConnectionState.DISCONNECTED,
                            )
                        },
                    )
            }
        }
    }

    override fun unsubscribe(id: String, changeType: SudoSubscriber.ChangeType) {
        this.logger.info("Unsubscribing from Sudo change notification.")

        when (changeType) {
            SudoSubscriber.ChangeType.CREATE -> {
                this.onCreateSudoSubscriptionManager.removeSubscriber(id)
            }
            SudoSubscriber.ChangeType.UPDATE -> {
                this.onUpdateSudoSubscriptionManager.removeSubscriber(id)
            }
            SudoSubscriber.ChangeType.DELETE -> {
                this.onDeleteSudoSubscriptionManager.removeSubscriber(id)
            }
        }
    }

    override fun unsubscribe(id: String) {
        this.logger.info("Unsubscribing from all Sudo change notifications.")
        this.unsubscribe(id, SudoSubscriber.ChangeType.CREATE)
        this.unsubscribe(id, SudoSubscriber.ChangeType.DELETE)
        this.unsubscribe(id, SudoSubscriber.ChangeType.UPDATE)
    }

    override fun unsubscribeAll() {
        this.logger.info("Unsubscribing all subscribers from Sudo change notification.")

        this.onCreateSudoSubscriptionManager.removeAllSubscribers()
        this.onUpdateSudoSubscriptionManager.removeAllSubscribers()
        this.onDeleteSudoSubscriptionManager.removeAllSubscribers()
    }

    override fun generateEncryptionKey(): String {
        return this.cryptoProvider.generateEncryptionKey()
    }

    override fun getSymmetricKeyId(): String? {
        return this.cryptoProvider.getSymmetricKeyId()
    }

    override fun importEncryptionKeys(keys: List<EncryptionKey>, currentKeyId: String) {
        this.cryptoProvider.importEncryptionKeys(keys, currentKeyId)
    }

    override fun exportEncryptionKeys(): List<EncryptionKey> {
        return this.cryptoProvider.exportEncryptionKeys()
    }

    private fun createSecureString(
        name: String,
        value: String,
    ): SecureClaimInput {
        val keyId = this.cryptoProvider.getSymmetricKeyId()

        if (keyId != null) {
            val algorithm = SymmetricKeyEncryptionAlgorithm.AES_CBC_PKCS7PADDING
            val encryptedData = this.cryptoProvider.encrypt(
                keyId,
                algorithm,
                value.toByteArray(),
            )

            return SecureClaimInput(
                version = 1,
                name = name,
                keyId = keyId,
                algorithm = algorithm.toString(),
                base64Data = Base64.encodeToString(encryptedData, Base64.NO_WRAP),
            )
        } else {
            throw SudoProfileException.FailedException("No symmetric key found.")
        }
    }

    private fun processSecureClaim(
        name: String,
        keyId: String,
        algorithm: String,
        base64Data: String,
    ): Claim {
        val algorithmSpec =
            SymmetricKeyEncryptionAlgorithm.fromString(algorithm)

        if (algorithmSpec != null) {
            val value = String(
                this.cryptoProvider.decrypt(
                    keyId,
                    algorithmSpec,
                    Base64.decode(base64Data, Base64.DEFAULT),
                ),
            )

            return Claim(name, Claim.Visibility.PRIVATE, Claim.Value.StringValue(value))
        } else {
            throw SudoProfileException.UnsupportedAlgorithmException()
        }
    }

    private suspend fun getSudo(id: String): Sudo? {
        return listSudos(ListOption.CACHE_ONLY).firstOrNull { it.id == id }
    }

    private suspend fun deleteSecureS3Objects(sudoId: String) {
        val sudo = this.getSudo(sudoId)
        require(sudo != null) { "Sudo not found." }

        for ((_, claim) in sudo.claims) {
            when (claim.visibility) {
                Claim.Visibility.PRIVATE -> {
                    when (claim.value) {
                        is Claim.Value.BlobValue -> {
                            val cacheEntry =
                                this.blobCache.get(claim.value.value)
                            if (cacheEntry != null) {
                                this.blobCache.remove(cacheEntry.id)
                            }
                        }
                        else -> {}
                    }
                }
                else -> {
                    // Currently other visibility types are not supported.
                }
            }
        }
    }

    private suspend fun processListSudos(
        items: List<ListSudosQuery.Item>,
        option: ListOption,
        processS3Object: Boolean,
    ): List<Sudo> {
        val sudos: MutableList<Sudo> = mutableListOf()

        for (item in items) {
            val sudo = Sudo(
                item.id,
                item.version,
                Date(item.createdAtEpochMs.toLong()),
                Date(item.updatedAtEpochMs.toLong()),
            )

            sudo.claims = item.claims
                .map {
                    it.name to this.processSecureClaim(
                        it.name,
                        it.keyId,
                        it.algorithm,
                        it.base64Data,
                    )
                }
                .toMap().toMutableMap()
            sudo.metadata = item.metadata.map {
                it.name to it.value
            }.toMap().toMutableMap()

            if (processS3Object) {
                for (obj in item.objects) {
                    // Check if we already have the S3 object in the cache. Return the cache entry
                    // if asked to fetch from cache but otherwise download the S3 object.
                    if (option == ListOption.CACHE_ONLY) {
                        val objectId = this.getS3ObjectIdFromKey(obj.key)
                        if (objectId != null) {
                            val entry = blobCache.get(objectId)
                            if (entry != null) {
                                sudo.claims[obj.name] =
                                    Claim(
                                        obj.name,
                                        Claim.Visibility.PRIVATE,
                                        Claim.Value.BlobValue(entry.toUri()),
                                    )
                            }
                        } else {
                            this.logger.error("Cannot determine the object ID from the key.")
                        }
                    } else {
                        val data =
                            this.s3Client.download(
                                obj.key,
                            )

                        val algorithmSpec =
                            SymmetricKeyEncryptionAlgorithm.fromString(obj.algorithm)
                        if (algorithmSpec != null) {
                            val decryptedData =
                                this.cryptoProvider.decrypt(
                                    obj.keyId,
                                    algorithmSpec,
                                    data,
                                )
                            val array = obj.key.split("/").toTypedArray()
                            val entry = blobCache.replace(
                                decryptedData,
                                array.last(),
                            )

                            sudo.claims[obj.name] =
                                Claim(
                                    obj.name,
                                    Claim.Visibility.PRIVATE,
                                    Claim.Value.BlobValue(entry.toUri()),
                                )
                        } else {
                            throw SudoProfileException.UnsupportedAlgorithmException("Unsupported algorithm found in secure S3 object.")
                        }
                    }
                }
            }

            sudos.add(sudo)
        }

        return sudos
    }

    private fun getS3ObjectIdFromKey(key: String): String? {
        val components = key.split("/")
        return components.lastOrNull()
    }

    /**
     * Helper to wrap any unhandled exceptions into a [SudoProfileException.FailedException]
     */
    private fun Exception.toFailedExceptionOrThrow(): Exception {
        return when (this) {
            is SudoProfileException -> this
            else -> SudoProfileException.FailedException(cause = this)
        }
    }
}
