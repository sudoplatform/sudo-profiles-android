/*
 * Copyright © 2022 Anonyome Labs, Inc. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package com.sudoplatform.sudoprofiles

import android.content.Context
import android.net.Uri
import android.util.Base64
import androidx.core.net.toFile
import com.amazonaws.mobileconnectors.appsync.AWSAppSyncClient
import com.amazonaws.mobileconnectors.appsync.AppSyncSubscriptionCall
import com.amazonaws.mobileconnectors.appsync.fetcher.AppSyncResponseFetchers
import com.apollographql.apollo.api.Response
import com.apollographql.apollo.exception.ApolloException
import com.sudoplatform.sudoapiclient.ApiClientManager
import com.sudoplatform.sudoconfigmanager.DefaultSudoConfigManager
import com.sudoplatform.sudoprofiles.type.CreateSudoInput
import com.sudoplatform.sudouser.SudoUserClient
import org.json.JSONObject
import java.util.Date
import com.sudoplatform.sudologging.Logger
import com.sudoplatform.sudoprofiles.exceptions.SudoProfileException
import com.sudoplatform.sudoprofiles.exceptions.SudoProfileException.Companion.toSudoProfileException
import com.sudoplatform.sudoprofiles.extensions.enqueue
import com.sudoplatform.sudoprofiles.type.DeleteSudoInput
import com.sudoplatform.sudoprofiles.type.UpdateSudoInput
import com.sudoplatform.sudoprofiles.type.GetOwnershipProofInput
import com.sudoplatform.sudoprofiles.type.SecureClaimInput
import com.sudoplatform.sudoprofiles.type.SecureS3ObjectInput
import kotlinx.coroutines.GlobalScope
import kotlinx.coroutines.launch
import kotlinx.coroutines.Dispatchers.IO

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
    RETURN_CACHED_ELSE_FETCH
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
        fun builder(context: Context,
                    sudoUserClient: SudoUserClient,
                    blobContainerURI: Uri) =
            Builder(
                context,
                sudoUserClient,
                blobContainerURI)
    }

    /**
     * Builder used to construct [SudoProfilesClient].
     */
    class Builder(
        private val context: Context,
        private val sudoUserClient: SudoUserClient,
        private val blobContainerURI: Uri
    ) {
        private var logger: Logger = DefaultLogger.instance
        private var config: JSONObject? = null
        private var maxSudos: Int = 10
        private var graphQLClient: AWSAppSyncClient? = null
        private var s3Client: S3Client? = null
        private var queryCache: QueryCache? = null
        private var idGenerator: IdGenerator = DefaultIdGenerator()
        private var cryptoProvider: CryptoProvider? = null

        /**
         * Provide the implementation of the [Logger] used for logging. If a value is not supplied
         * a default implementation will be used.
         */
        fun setLogger(logger: Logger) = also { this.logger = logger }

        /**
         * Provide the Configuration Parameters
         */
        fun seConfig(config: JSONObject) = also { this.config = config }

        /**
         * Provide the maximum number of Sudos to cap the queries to.  If a value is not supplied
         * a default of 10 will be set.
         */
        fun setMaxSudos(maxSudos: Int) = also { this.maxSudos = maxSudos }

        /**
         * Provide an [AWSAppSyncClient] for the [SudoProfilesClient]. If this is not
         * supplied, an [AWSAppSyncClient] will be obtained from [ApiClientManager].
         */
        fun setGraphQLClient(graphQLClient: AWSAppSyncClient) = also { this.graphQLClient = graphQLClient }

        /**
         * Provide an [S3Client] to use for AWS S3 related operations.  If a value is not supplied
         * a default implementation will be used.
         */
        fun setS3Client(s3Client: S3Client) = also { this.s3Client = s3Client }

        /**
         * Provide an [QueryCache] to use.  If a value is not supplied
         * a default implementation will be provided.
         */
        fun setQueryCache(queryCache: QueryCache) = also { this.queryCache = queryCache }

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

            val graphQLClient = this.graphQLClient ?: ApiClientManager.getClient(
                this.context,
                this.sudoUserClient
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
                    CONFIG_BUCKET
                ) as String?
                ?: throw SudoProfileException.InvalidConfigException("Bucket name missing.")
            val region =
                sudoServiceConfig.opt(CONFIG_REGION) as String? ?: identityServiceConfig.opt(
                    CONFIG_REGION
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
                this.s3Client ?:
                    DefaultS3Client(this.context, this.sudoUserClient, region, bucket),
                this.queryCache ?:
                    DefaultQueryCache(graphQLClient),
                this.idGenerator,
                this.cryptoProvider
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
 * @param queryCache optional GraphQL query cache. Mainly used for unit testing.
 * @param idGenerator optional GUID generator to use. Mainly used for unit testing.
 */
class DefaultSudoProfilesClient constructor(
    private val context: Context,
    private val sudoUserClient: SudoUserClient,
    blobContainerURI: Uri,
    private val logger: Logger = DefaultLogger.instance,
    config: JSONObject? = null,
    maxSudos: Int = 10,
    graphQLClient: AWSAppSyncClient? = null,
    s3Client: S3Client? = null,
    queryCache: QueryCache? = null,
    idGenerator: IdGenerator = DefaultIdGenerator(),
    cryptoProvider: CryptoProvider? = null
) : SudoProfilesClient {

    companion object {
        private const val CONFIG_NAMESPACE_SUDO_SERVICE = "sudoService"
        private const val CONFIG_REGION = "region"
        private const val CONFIG_BUCKET = "bucket"

        private const val DEFAULT_KEY_NAMESPACE = "ss"
    }

    override val version: String = "8.0.0"

    /**
     * GraphQL client used for calling Sudo service API.
     */
    private val graphQLClient: AWSAppSyncClient

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
    private val defaultQuery: ListSudosQuery

    /**
     * GraphQL client query cache.
     */
    private val queryCache: QueryCache

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

        this.graphQLClient = graphQLClient ?: ApiClientManager.getClient(
            context,
            this.sudoUserClient
        )

        this.s3Client =
            s3Client ?: DefaultS3Client(this.context, this.sudoUserClient, region, bucket)

        this.cryptoProvider = cryptoProvider ?: DefaultCryptoProvider(DEFAULT_KEY_NAMESPACE, context)

        if (this.cryptoProvider.getSymmetricKeyId() == null) {
            this.cryptoProvider.generateEncryptionKey()
        }

        this.idGenerator = idGenerator

        this.blobCache = BlobCache(blobContainerURI, this.idGenerator)

        this.defaultQuery = ListSudosQuery(maxSudos, null)

        this.queryCache = queryCache ?: DefaultQueryCache(this.graphQLClient)

        this.onCreateSudoSubscriptionManager = SubscriptionManager()
        this.onUpdateSudoSubscriptionManager = SubscriptionManager()
        this.onDeleteSudoSubscriptionManager = SubscriptionManager()
    }

    override suspend fun createSudo(sudo: Sudo): Sudo
    {
        this.logger.info("Creating a Sudo.")

        val keyId = this.cryptoProvider.getSymmetricKeyId()
        require(keyId != null) { "Symmetric key missing." }

        try {
            val input = CreateSudoInput
                .builder()
                .claims(listOf())
                .objects(listOf())
                .build()

            val mutation = CreateSudoMutation
                .builder()
                .input(input)
                .build()

            val response = this.graphQLClient.mutate(mutation)
                .enqueue()

            if(response.hasErrors()) {
                throw response.errors().first().toSudoProfileException()
            }

            val result = response.data()?.createSudo()
            if (result != null) {
                sudo.id = result.id()
                sudo.version = result.version()
                sudo.createdAt = Date(result.createdAtEpochMs().toLong())
                sudo.updatedAt = Date(result.updatedAtEpochMs().toLong())

                return updateSudo(sudo)
            } else {
                throw SudoProfileException.FailedException("Mutation succeeded but output was null.")
            }
        } catch (e: Exception) {
           throw e.toFailedExceptionOrThrow()
        }
    }

    override suspend fun updateSudo(sudo: Sudo) : Sudo {
        this.logger.info("Updating a Sudo.")

        val sudoId = sudo.id
        require(sudoId != null) { "Sudo ID was null." }

        val keyId = this.cryptoProvider.getSymmetricKeyId()
        require(keyId != null) { "Symmetric key missing." }

        try {
            val secureClaims: MutableList<SecureClaimInput> = mutableListOf()
            val secureS3Objects: MutableList<SecureS3ObjectInput> = mutableListOf()

            for ((name, claim) in sudo.claims) {
                if(claim.visibility === Claim.Visibility.PRIVATE) {
                    when (claim.value) {
                        is Claim.Value.BlobValue -> {
                            val file = claim.value.value.normalizeScheme().toFile()
                            val data = file.readBytes()

                            val cacheEntry =
                                this.blobCache.replace(
                                    data,
                                    "sudo/$sudoId/${claim.name}"
                                )

                            try {
                                sudo.claims[name] = Claim(
                                    name,
                                    claim.visibility,
                                    Claim.Value.BlobValue(cacheEntry.toUri())
                                )

                                val algorithm =
                                    SymmetricKeyEncryptionAlgorithm.AES_CBC_PKCS7PADDING
                                val encrypted =
                                    this.cryptoProvider.encrypt(
                                        keyId,
                                        algorithm,
                                        data
                                    )

                                val key = this.s3Client.upload(
                                    encrypted,
                                    cacheEntry.id
                                )

                                secureS3Objects.add(
                                    SecureS3ObjectInput
                                        .builder()
                                        .version(1)
                                        .name(name)
                                        .algorithm(algorithm.toString())
                                        .keyId(keyId)
                                        .bucket(this.s3Client.bucket)
                                        .region(this.s3Client.region)
                                        .key(key)
                                        .build()
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
                                    claim.value.value
                                )
                            )
                        }
                    }
                }
            }

            val input = UpdateSudoInput
                .builder()
                .id(sudoId)
                .expectedVersion(sudo.version)
                .claims(secureClaims)
                .objects(secureS3Objects)
                .build()

            val mutation = UpdateSudoMutation
                .builder()
                .input(input)
                .build()

            val response = this.graphQLClient.mutate(mutation)
                .enqueue()

            if(response.hasErrors()) {
                throw response.errors().first().toSudoProfileException()
            }

            val output = response.data()?.updateSudo()
            if(output != null) {
                sudo.id = output.id()
                sudo.version = output.version()
                sudo.createdAt = Date(output.createdAtEpochMs().toLong())
                sudo.updatedAt = Date(output.updatedAtEpochMs().toLong())

                val item = mapSudo(output)
                this.queryCache.replace(this.defaultQuery, item)

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

            val input = DeleteSudoInput
                .builder()
                .id(sudoId)
                .expectedVersion(sudo.version)
                .build()

            val mutation = DeleteSudoMutation
                .builder()
                .input(input)
                .build()

            val response = this.graphQLClient.mutate(mutation)
                .enqueue()

            if(response.hasErrors()) {
                throw response.errors().first().toSudoProfileException()
            }
        } catch (e: Exception) {
            throw e.toFailedExceptionOrThrow()
        }
    }

    override suspend fun listSudos(option: ListOption) : List<Sudo> {
        this.logger.info("Listing Sudos.")

        try {
            val responseFetcher = when (option) {
                ListOption.CACHE_ONLY -> {
                    AppSyncResponseFetchers.CACHE_ONLY
                }
                ListOption.REMOTE_ONLY -> {
                    AppSyncResponseFetchers.NETWORK_ONLY
                }
                ListOption.RETURN_CACHED_ELSE_FETCH -> {
                    AppSyncResponseFetchers.CACHE_FIRST
                }
            }

            val response = this.graphQLClient.query(this.defaultQuery)
                .responseFetcher(responseFetcher)
                .enqueue()

            if(response.hasErrors()) {
                throw response.errors().first().toSudoProfileException()
            }

            var sudos: List<Sudo> = listOf()

            // Iterate over Sudos.
            val items = response.data()?.listSudos()?.items()
            if (items != null) {
                sudos = this.processListSudos(
                    items,
                    option,
                    true
                )
            }

            return sudos

        } catch (e: Exception) {
            throw e.toFailedExceptionOrThrow()
        }
    }

    override fun reset() {
        this.logger.info("Resetting client.")

        this.graphQLClient.clearCaches()
        this.blobCache.reset()
        this.cryptoProvider.reset()
    }

    override suspend fun getOwnershipProof(sudo: Sudo, audience: String) : String {
        this.logger.info("Getting a Sudo ownership proof.")

        val sudoId = sudo.id
        require(sudoId != null) { "Sudo ID was null." }

        try {
            val input = GetOwnershipProofInput
                .builder()
                .sudoId(sudoId)
                .audience(audience)
                .build()

            val mutation = GetOwnershipProofMutation.
                builder()
                .input(input)
                .build()


            val response = this.graphQLClient.mutate(mutation)
                .enqueue()

            if(response.hasErrors()) {
                 throw response.errors().first().toSudoProfileException()
            }

            val output = response.data()?.ownershipProof
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
        subscriber: SudoSubscriber
    ) {
        this.logger.info("Subscribing for Sudo change notification.")

        val owner = this.sudoUserClient.getSubject()
        require(
            owner != null
        ) { "Owner was null. The client may not be signed in." }

        when (changeType) {
            SudoSubscriber.ChangeType.CREATE -> {
                this.onCreateSudoSubscriptionManager.replaceSubscriber(id, subscriber)
                if (this.onCreateSudoSubscriptionManager.watcher == null) {

                    val subscription = OnCreateSudoSubscription
                        .builder()
                        .owner(owner)
                        .build()

                    val watcher = this.graphQLClient.subscribe(subscription)

                    this.onCreateSudoSubscriptionManager.watcher = watcher

                    executeCreateSudoSubscriptionWatcher()

                    this.onCreateSudoSubscriptionManager.connectionStatusChanged(
                        SudoSubscriber.ConnectionState.CONNECTED
                    )
                }
            }
            SudoSubscriber.ChangeType.DELETE -> {
                this.onDeleteSudoSubscriptionManager.replaceSubscriber(id, subscriber)
                if (this.onDeleteSudoSubscriptionManager.watcher == null) {

                    val subscription = OnDeleteSudoSubscription
                        .builder()
                        .owner(owner)
                        .build()

                    val watcher = this.graphQLClient.subscribe(subscription)

                    this.onDeleteSudoSubscriptionManager.watcher = watcher

                    executeDeleteSudoSubscriptionWatcher()

                    this@DefaultSudoProfilesClient.onDeleteSudoSubscriptionManager.connectionStatusChanged(
                        SudoSubscriber.ConnectionState.CONNECTED
                    )
                }
            }
            SudoSubscriber.ChangeType.UPDATE -> {
                this.onUpdateSudoSubscriptionManager.replaceSubscriber(id, subscriber)
                if (this.onUpdateSudoSubscriptionManager.watcher == null) {

                    val subscription = OnUpdateSudoSubscription
                        .builder()
                        .owner(owner)
                        .build()

                    val watcher = this.graphQLClient.subscribe(subscription)

                    this.onUpdateSudoSubscriptionManager.watcher = watcher

                    executeUpdateSudoSubscriptionWatcher()

                    this@DefaultSudoProfilesClient.onUpdateSudoSubscriptionManager.connectionStatusChanged(
                        SudoSubscriber.ConnectionState.CONNECTED
                    )
                }
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

    private fun executeUpdateSudoSubscriptionWatcher() {
        this@DefaultSudoProfilesClient.onUpdateSudoSubscriptionManager.watcher?.execute(
            object :
                AppSyncSubscriptionCall.Callback<OnUpdateSudoSubscription.Data> {
                override fun onCompleted() {
                    // Subscription was terminated. Notify the subscribers.
                    this@DefaultSudoProfilesClient.onUpdateSudoSubscriptionManager.connectionStatusChanged(
                        SudoSubscriber.ConnectionState.DISCONNECTED
                    )
                }

                override fun onFailure(e: ApolloException) {
                    // Failed create a subscription. Notify the subscribers.
                    this@DefaultSudoProfilesClient.onUpdateSudoSubscriptionManager.connectionStatusChanged(
                        SudoSubscriber.ConnectionState.DISCONNECTED
                    )
                }

                override fun onResponse(response: Response<OnUpdateSudoSubscription.Data>) {
                    GlobalScope.launch(IO) {
                        try {
                            val error = response.errors().firstOrNull()
                            if (error != null) {
                                this@DefaultSudoProfilesClient.logger.error("Subscription response contained error: $error")
                            } else {
                                val item = response.data()?.onUpdateSudo()
                                if (item != null) {
                                    val listSudosQueryItem = ListSudosQuery.Item(
                                        item.__typename(),
                                        item.id(),
                                        item.claims().map {
                                            ListSudosQuery.Claim(
                                                it.__typename(),
                                                it.name(),
                                                it.version(),
                                                it.algorithm(),
                                                it.keyId(),
                                                it.base64Data()
                                            )
                                        },
                                        item.objects().map {
                                            ListSudosQuery.Object(
                                                it.__typename(),
                                                it.name(),
                                                it.version(),
                                                it.algorithm(),
                                                it.keyId(),
                                                it.bucket(),
                                                it.region(),
                                                it.key()
                                            )
                                        },
                                        item.metadata().map {
                                            ListSudosQuery.Metadatum(
                                                it.__typename(),
                                                it.name(),
                                                it.value()
                                            )
                                        },
                                        item.createdAtEpochMs(),
                                        item.updatedAtEpochMs(),
                                        item.version(),
                                        item.owner()
                                    )

                                    val sudos =
                                        this@DefaultSudoProfilesClient.processListSudos(
                                            listOf(listSudosQueryItem),
                                            ListOption.CACHE_ONLY,
                                            false
                                        )

                                    val sudo = sudos.firstOrNull()
                                    if (sudo != null) {
                                        // Remove the deleted item from the cache.
                                        val items =
                                            this@DefaultSudoProfilesClient.getCachedQueryItems()
                                                ?.filter { element -> element.id != listSudosQueryItem.id() }
                                                ?.toMutableList()
                                        if (items != null) {
                                            items.add(listSudosQueryItem)
                                            this@DefaultSudoProfilesClient.replaceCachedQueryItems(
                                                items
                                            )
                                        }

                                        this@DefaultSudoProfilesClient.onUpdateSudoSubscriptionManager.sudoChanged(
                                            SudoSubscriber.ChangeType.UPDATE,
                                            sudo
                                        )
                                    }
                                }
                            }
                        } catch (e: Exception) {
                            this@DefaultSudoProfilesClient.logger.error("Failed to process the subscription response: $e")
                        }
                    }
                }
            }
        )
    }

    private fun executeDeleteSudoSubscriptionWatcher() {
        this@DefaultSudoProfilesClient.onDeleteSudoSubscriptionManager.watcher?.execute(
            object :
                AppSyncSubscriptionCall.Callback<OnDeleteSudoSubscription.Data> {
                override fun onCompleted() {
                    // Subscription was terminated. Notify the subscribers.
                    this@DefaultSudoProfilesClient.onDeleteSudoSubscriptionManager.connectionStatusChanged(
                        SudoSubscriber.ConnectionState.DISCONNECTED
                    )
                }

                override fun onFailure(e: ApolloException) {
                    // Failed create a subscription. Notify the subscribers.
                    this@DefaultSudoProfilesClient.onDeleteSudoSubscriptionManager.connectionStatusChanged(
                        SudoSubscriber.ConnectionState.DISCONNECTED
                    )
                }

                override fun onResponse(response: Response<OnDeleteSudoSubscription.Data>) {
                    GlobalScope.launch(IO) {
                        try {
                            val error = response.errors().firstOrNull()
                            if (error != null) {
                                this@DefaultSudoProfilesClient.logger.error("Subscription response contained error: $error")
                            } else {
                                val item = response.data()?.onDeleteSudo()
                                if (item != null) {
                                    val listSudosQueryItem = ListSudosQuery.Item(
                                        item.__typename(),
                                        item.id(),
                                        item.claims().map {
                                            ListSudosQuery.Claim(
                                                it.__typename(),
                                                it.name(),
                                                it.version(),
                                                it.algorithm(),
                                                it.keyId(),
                                                it.base64Data()
                                            )
                                        },
                                        item.objects().map {
                                            ListSudosQuery.Object(
                                                it.__typename(),
                                                it.name(),
                                                it.version(),
                                                it.algorithm(),
                                                it.keyId(),
                                                it.bucket(),
                                                it.region(),
                                                it.key()
                                            )
                                        },
                                        item.metadata().map {
                                            ListSudosQuery.Metadatum(
                                                it.__typename(),
                                                it.name(),
                                                it.value()
                                            )
                                        },
                                        item.createdAtEpochMs(),
                                        item.updatedAtEpochMs(),
                                        item.version(),
                                        item.owner()
                                    )

                                    val sudos =
                                        this@DefaultSudoProfilesClient.processListSudos(
                                            listOf(listSudosQueryItem),
                                            ListOption.CACHE_ONLY,
                                            false
                                        )

                                    val sudo = sudos.firstOrNull()
                                    if (sudo != null) {
                                        // Remove the deleted item from the cache.
                                        val items =
                                            this@DefaultSudoProfilesClient.getCachedQueryItems()
                                        if (items != null) {
                                            this@DefaultSudoProfilesClient.replaceCachedQueryItems(
                                                items.filter { element -> element.id != listSudosQueryItem.id() })
                                        }

                                        this@DefaultSudoProfilesClient.onDeleteSudoSubscriptionManager.sudoChanged(
                                            SudoSubscriber.ChangeType.DELETE,
                                            sudo
                                        )
                                    }
                                }
                            }
                        } catch (e: Exception) {
                            this@DefaultSudoProfilesClient.logger.error("Failed to process the subscription response: $e")
                        }
                    }
                }
            }
        )
    }

    private fun executeCreateSudoSubscriptionWatcher() {

        this@DefaultSudoProfilesClient.onCreateSudoSubscriptionManager.watcher?.execute(
            object :
                AppSyncSubscriptionCall.Callback<OnCreateSudoSubscription.Data> {
                override fun onCompleted() {
                    // Subscription was terminated. Notify the subscribers.
                    this@DefaultSudoProfilesClient.onCreateSudoSubscriptionManager.connectionStatusChanged(
                        SudoSubscriber.ConnectionState.DISCONNECTED
                    )
                }

                override fun onFailure(e: ApolloException) {
                    // Failed create a subscription. Notify the subscribers.
                    this@DefaultSudoProfilesClient.onCreateSudoSubscriptionManager.connectionStatusChanged(
                        SudoSubscriber.ConnectionState.DISCONNECTED
                    )
                }

                override fun onResponse(response: Response<OnCreateSudoSubscription.Data>) {
                    GlobalScope.launch(IO) {
                        try {
                            val error = response.errors().firstOrNull()
                            if (error != null) {
                                this@DefaultSudoProfilesClient.logger.error("Subscription response contained error: $error")
                            } else {
                                val item = response.data()?.onCreateSudo()
                                if (item != null) {
                                    val listSudosQueryItem = ListSudosQuery.Item(
                                        item.__typename(),
                                        item.id(),
                                        item.claims().map {
                                            ListSudosQuery.Claim(
                                                it.__typename(),
                                                it.name(),
                                                it.version(),
                                                it.algorithm(),
                                                it.keyId(),
                                                it.base64Data()
                                            )
                                        },
                                        item.objects().map {
                                            ListSudosQuery.Object(
                                                it.__typename(),
                                                it.name(),
                                                it.version(),
                                                it.algorithm(),
                                                it.keyId(),
                                                it.bucket(),
                                                it.region(),
                                                it.key()
                                            )
                                        },
                                        item.metadata().map {
                                            ListSudosQuery.Metadatum(
                                                it.__typename(),
                                                it.name(),
                                                it.value()
                                            )
                                        },
                                        item.createdAtEpochMs(),
                                        item.updatedAtEpochMs(),
                                        item.version(),
                                        item.owner()
                                    )

                                    val sudos =
                                        this@DefaultSudoProfilesClient.processListSudos(
                                            listOf(listSudosQueryItem),
                                            ListOption.CACHE_ONLY,
                                            false
                                        )

                                    val sudo = sudos.firstOrNull()
                                    if (sudo != null) {
                                        // Add the new item to the cache.
                                        val items =
                                            this@DefaultSudoProfilesClient.getCachedQueryItems()
                                                ?.toMutableList()
                                        if (items != null) {
                                            items.add(listSudosQueryItem)
                                            this@DefaultSudoProfilesClient.replaceCachedQueryItems(
                                                items
                                            )
                                        }

                                        this@DefaultSudoProfilesClient.onCreateSudoSubscriptionManager.sudoChanged(
                                            SudoSubscriber.ChangeType.CREATE,
                                            sudo
                                        )
                                    }
                                }
                            }
                        } catch (e: Exception) {
                            this@DefaultSudoProfilesClient.logger.error("Failed to process the subscription response: $e")
                        }
                    }
                }
            }
        )
    }

    private fun mapSudo(updateSudo: UpdateSudoMutation.UpdateSudo) : ListSudosQuery.Item {
        return ListSudosQuery.Item(
            "Sudo",
            updateSudo.id,
            updateSudo.claims().map {
                ListSudosQuery.Claim(
                    "SecureClaim",
                    it.name(),
                    it.version(),
                    it.algorithm(),
                    it.keyId(),
                    it.base64Data()
                )
            },
            updateSudo.objects().map {
                ListSudosQuery.Object(
                    "SecureS3Object",
                    it.name(),
                    it.version(),
                    it.algorithm(),
                    it.keyId(),
                    it.bucket(),
                    it.region(),
                    it.key()
                )
            },
            updateSudo.metadata().map {
                ListSudosQuery.Metadatum(
                    "Attribute",
                    it.name(),
                    it.value()
                )
            },
            updateSudo.createdAtEpochMs(),
            updateSudo.updatedAtEpochMs(),
            updateSudo.version(),
            updateSudo.owner()
        )
    }

    private fun createSecureString(
        name: String,
        value: String
    ): SecureClaimInput {
        val keyId = this.cryptoProvider.getSymmetricKeyId()

        if (keyId != null) {
            val algorithm = SymmetricKeyEncryptionAlgorithm.AES_CBC_PKCS7PADDING
            val encryptedData = this.cryptoProvider.encrypt(
                keyId,
                algorithm,
                value.toByteArray()
            )

            return SecureClaimInput
                .builder()
                .version(1)
                .name(name)
                .keyId(keyId)
                .algorithm(algorithm.toString())
                .base64Data(Base64.encodeToString(encryptedData, Base64.NO_WRAP))
                .build()
        } else {
            throw SudoProfileException.FailedException("No symmetric key found.")
        }
    }

    private fun processSecureClaim(
        name: String,
        keyId: String,
        algorithm: String,
        base64Data: String
    ): Claim {
        val algorithmSpec =
            SymmetricKeyEncryptionAlgorithm.fromString(algorithm)

        if (algorithmSpec != null) {
            val value = String(
                this.cryptoProvider.decrypt(
                    keyId,
                    algorithmSpec,
                    Base64.decode(base64Data, Base64.DEFAULT)
                )
            )

            return Claim(name, Claim.Visibility.PRIVATE, Claim.Value.StringValue(value))
        } else {
            throw SudoProfileException.UnsupportedAlgorithmException()
        }
    }

    private suspend fun getSudo(id: String): Sudo? {
        return listSudos(ListOption.CACHE_ONLY).firstOrNull() { it.id == id}
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
        processS3Object: Boolean
    ): List<Sudo> {
        val sudos: MutableList<Sudo> = mutableListOf()

        for (item in items) {
            val sudo = Sudo(
                item.id(),
                item.version,
                Date(item.createdAtEpochMs().toLong()),
                Date(item.updatedAtEpochMs().toLong())
            )

            sudo.claims = item.claims()
                .map {
                    it.name() to this.processSecureClaim(
                        it.name(),
                        it.keyId(),
                        it.algorithm(),
                        it.base64Data()
                    )
                }
                .toMap().toMutableMap()
            sudo.metadata = item.metadata().map {
                it.name() to it.value()
            }.toMap().toMutableMap()

            if (processS3Object) {
                for (obj in item.objects) {
                    // Check if we already have the S3 object in the cache. Return the cache entry
                    // if asked to fetch from cache but otherwise download the S3 object.
                    if (option == ListOption.CACHE_ONLY) {
                        val objectId = this.getS3ObjectIdFromKey(obj.key())
                        if (objectId != null) {
                            val entry = blobCache.get(objectId)
                            if (entry != null) {
                                sudo.claims[obj.name] =
                                    Claim(
                                        obj.name,
                                        Claim.Visibility.PRIVATE,
                                        Claim.Value.BlobValue(entry.toUri())
                                    )
                            }
                        } else {
                            this.logger.error("Cannot determine the object ID from the key.")
                        }
                    } else {
                        val data =
                            this.s3Client.download(
                                obj.key
                            )

                        val algorithmSpec =
                            SymmetricKeyEncryptionAlgorithm.fromString(obj.algorithm)
                        if (algorithmSpec != null) {
                            val decryptedData =
                                this.cryptoProvider.decrypt(
                                    obj.keyId,
                                    algorithmSpec,
                                    data
                                )
                            val array = obj.key.split("/").toTypedArray()
                            val entry = blobCache.replace(
                                decryptedData,
                                array.last()
                            )

                            sudo.claims[obj.name] =
                                Claim(
                                    obj.name,
                                    Claim.Visibility.PRIVATE,
                                    Claim.Value.BlobValue(entry.toUri())
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

    private fun replaceCachedQueryItems(items: List<ListSudosQuery.Item>) {
        // Update the query cache. Currently the store callback interface is not public so we have to assume
        // the update is always successfully.
        val data = ListSudosQuery.Data(ListSudosQuery.ListSudos("ModelSudoConnection", items, null))
        this.graphQLClient.store.write(
            this.defaultQuery,
            data
        ).enqueue(null)
    }

    private suspend fun getCachedQueryItems(): List<ListSudosQuery.Item>? {

        val response =
            this.graphQLClient.query(this@DefaultSudoProfilesClient.defaultQuery)
                .responseFetcher(AppSyncResponseFetchers.CACHE_ONLY)
                .enqueue()

        if(response.hasErrors()) {
            throw response.errors().first().toSudoProfileException()
        }

        return response.data()?.listSudos?.items
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
