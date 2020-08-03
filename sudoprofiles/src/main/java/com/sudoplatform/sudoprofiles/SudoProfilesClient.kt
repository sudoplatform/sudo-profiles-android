/**
 * Copyright © 2020 Anonyome Labs, Inc. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package com.sudoplatform.sudoprofiles

import android.content.Context
import android.util.Base64
import com.amazonaws.mobileconnectors.appsync.AWSAppSyncClient
import com.amazonaws.mobileconnectors.appsync.AppSyncSubscriptionCall
import com.amazonaws.mobileconnectors.appsync.fetcher.AppSyncResponseFetchers
import com.apollographql.apollo.api.Response
import com.apollographql.apollo.exception.ApolloException
import com.sudoplatform.sudoapiclient.ApiClientManager
import com.sudoplatform.sudoconfigmanager.DefaultSudoConfigManager
import com.sudoplatform.sudoprofiles.type.*
import com.sudoplatform.sudouser.SudoUserClient
import com.sudoplatform.sudouser.SymmetricKeyEncryptionAlgorithm
import org.json.JSONObject
import java.io.File
import java.net.URI
import java.util.*
import com.sudoplatform.sudologging.Logger
import com.sudoplatform.sudoprofiles.exceptions.*
import com.sudoplatform.sudoprofiles.exceptions.SudoProfileException.Companion.toApiException
import com.sudoplatform.sudoprofiles.exceptions.SudoProfileException.Companion.toSudoProfileException
import com.sudoplatform.sudoprofiles.extensions.enqueue
import kotlinx.coroutines.*
import kotlinx.coroutines.Dispatchers.IO

/**
 * Generic API result. The API can fail with an error or complete successfully.
 */
sealed class ApiResult {
    /**
     * Encapsulates a successful API result.
     *
     */
    data class Success(val description: String = "API completed successfully.") : ApiResult()

    /**
     * Encapsulates a failed API result.
     *
     * @param error [Throwable] encapsulating the error detail.
     */
    data class Failure(val error: Throwable) : ApiResult()
}

/**
 * Result returned by API for creating a new Sudo. The API can fail with an
 * error or return the newly created Sudo.
 */
sealed class CreateSudoResult {
    /**
     * Encapsulates a successful Sudo creation result.
     *
     * @param sudo newly created Sudo.
     */
    data class Success(val sudo: Sudo) : CreateSudoResult()

    /**
     * Encapsulates a failed Sudo creation result.
     *
     * @param error [Throwable] encapsulating the error detail.
     */
    data class Failure(val error: Throwable) : CreateSudoResult()
}

/**
 * Result returned by API for updating a Sudo. The API can fail with an
 * error or return the updated Sudo.
 */
sealed class UpdateSudoResult {
    /**
     * Encapsulates a successful Sudo update result.
     *
     * @param sudo updated Sudo.
     */
    data class Success(val sudo: Sudo) : UpdateSudoResult()

    /**
     * Encapsulates a failed Sudo update result.
     *
     * @param error [Throwable] encapsulating the error detail.
     */
    data class Failure(val error: Throwable) : UpdateSudoResult()
}

/**
 * Result returned by API for listing Sudos. The API can fail with an
 * error or return the list of Sudos.
 */
sealed class ListSudosResult {
    /**
     * Encapsulates a successful list Sudos result.
     *
     * @param sudos list of Sudos owned by the currently signed in user.
     */
    data class Success(val sudos: List<Sudo>) : ListSudosResult()

    /**
     * Encapsulates a failed list Sudos result.
     *
     * @param error [Throwable] encapsulating the error detail.
     */
    data class Failure(val error: Throwable) : ListSudosResult()
}

/**
 * Result returned by API for getting a Sudo ownership proof. The API can
 * failed with an error or return the Sudo ownership proof.
 */
sealed class GetOwnershipProofResult {
    /**
     * Encapsulates a successful get ownership proof result.
     *
     * @param jwt ownership proof in form of a JWT.
     */
    data class Success(val jwt: String) : GetOwnershipProofResult()

    /**
     * Encapsulates a failed get ownership proof result.
     *
     * @param error [Throwable] encapsulating the error detail.
     */
    data class Failure(val error: Throwable) : GetOwnershipProofResult()
}

/**
 * Result returned by API for redeeming a token to grant additional entitlements.
 * The API can failed with an error or return the resulting entitlements.
 */
sealed class RedeemResult {
    /**
     * Encapsulates a successful redeem result.
     *
     * @param entitlements resulting entitlements.
     */
    data class Success(val entitlements: List<Entitlement>) : RedeemResult()

    /**
     * Encapsulates a failed redeem result.
     *
     * @param error [Throwable] encapsulating the error detail.
     */
    data class Failure(val error: Throwable) : RedeemResult()
}

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
    REMOTE_ONLY
}

/**
 * Interface encapsulating a library of functions for calling Sudo service and managing Sudos.
 */
interface SudoProfilesClient {

    companion object {
        private const val CONFIG_NAMESPACE_IDENTITY_SERVICE = "identityService"
        private const val CONFIG_REGION = "region"
        private const val CONFIG_BUCKET = "bucket"

        /**
         * Creates a [Builder] for [SudoProfilesClient].
         */
        fun builder(context: Context,
                    sudoUserClient: SudoUserClient,
                    blobContainerURI: URI) =
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
        private val blobContainerURI: URI
    ) {
        private var logger: Logger = DefaultLogger.instance
        private var config: JSONObject? = null
        private var maxSudos: Int = 10
        private var graphQLClient: AWSAppSyncClient? = null
        private var s3Client: S3Client? = null
        private var queryCache: QueryCache? = null
        private var idGenerator: IdGenerator = DefaultIdGenerator()


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

            val bucketConfig = identityServiceConfig?.get(CONFIG_BUCKET)
            val bucket = bucketConfig as String
            val region = identityServiceConfig.get(CONFIG_REGION) as String

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
                this.idGenerator
            )
        }
    }

    /**
     * Client version.
     */
    val version: String

    /**
     * Creates a new Sudo.
     *
     * @param sudo Sudo to create.
     * @param callback callback for returning Sudo creation result or error.
     */
    @Deprecated(
        message="This is deprecated and will be removed in the future.",
        replaceWith = ReplaceWith("createSudo(sudo)")
    )
    fun createSudo(sudo: Sudo, callback: (CreateSudoResult) -> Unit)

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
     * @param callback callback for returning Sudo update result or error.
     */
    @Deprecated(
        message="This is deprecated and will be removed in the future.",
        replaceWith = ReplaceWith("updateSudo(sudo)")
    )
    fun updateSudo(sudo: Sudo, callback: (UpdateSudoResult) -> Unit)

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
     * @param callback callback for returning Sudo deletion result or error.
     */
    @Deprecated(
        message="This is deprecated and will be removed in the future.",
        replaceWith = ReplaceWith("deleteSudo(sudo)")
    )
    fun deleteSudo(sudo: Sudo, callback: (ApiResult) -> Unit)

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
     * @param callback callback for returning list Sudos result or error.
     */
    @Deprecated(
        message="This is deprecated and will be removed in the future.",
        replaceWith = ReplaceWith("listSudos(option)")
    )
    fun listSudos(option: ListOption, callback: (ListSudosResult) -> Unit)

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
     *  @param callback callback for returning get ownership proof result or error.
     */
    @Deprecated(
        message="This is deprecated and will be removed in the future.",
        replaceWith = ReplaceWith("getOwnershipProof(sudo, audience)")
    )
    fun getOwnershipProof(sudo: Sudo, audience: String, callback: (GetOwnershipProofResult) -> Unit)

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
     * Redeem a token to be granted additional entitlements.
     *
     * @param token Token.
     * @param type Token type. Currently only valid value is "entitlements" but this maybe extended in future.
     * @param callback callback for returning redeem result or error.
     */
    @Deprecated(
        message="This is deprecated and will be removed in the future.",
        replaceWith = ReplaceWith("redeem(token, type)")
    )
    fun redeem(token: String, type: String, callback: (RedeemResult) -> Unit)

    /**
     * Redeem a token to be granted additional entitlements.
     *
     * @param token Token.
     * @param type Token type. Currently only valid value is "entitlements" but this maybe extended in future.
     * @return List<Entitlement>: A list of entitlements
     */
    suspend fun redeem(token: String, type: String): List<Entitlement>

    /**
     * Subscribes to be notified of new, updated or deleted Sudos. Blob data is not downloaded automatically
     * so the caller is expected to use `listSudos` API if they need to access any associated blobs.
     *
     * @param id unique ID for the subscriber.
     * @param changeType change type to subscribe to.
     * @param subscriber subscriber to notify.
     */
    @Deprecated(
        message="This is deprecated and will be removed in the future.",
        replaceWith = ReplaceWith("subscribeAsync(id, changeType, subscriber)")
    )
    fun subscribe(id: String, changeType: SudoSubscriber.ChangeType, subscriber: SudoSubscriber)

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
    @Deprecated(
        message="This is deprecated and will be removed in the future.",
        replaceWith = ReplaceWith("subscribeAsync(id, subscriber)")
    )
    fun subscribe(id: String, subscriber: SudoSubscriber)

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
     * Unsubscribe all subscribers from receiving notifications about new, updated or deleted Sudos.
     */
    fun unsubscribeAll()
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
    blobContainerURI: URI,
    private val logger: Logger = DefaultLogger.instance,
    config: JSONObject? = null,
    maxSudos: Int = 10,
    graphQLClient: AWSAppSyncClient? = null,
    s3Client: S3Client? = null,
    queryCache: QueryCache? = null,
    idGenerator: IdGenerator = DefaultIdGenerator()
) : SudoProfilesClient {

    companion object {
        private const val CONFIG_NAMESPACE_IDENTITY_SERVICE = "identityService"
        private const val CONFIG_REGION = "region"
        private const val CONFIG_BUCKET = "bucket"
    }

    override val version: String = "3.0.6"

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
        val configManager = DefaultSudoConfigManager(context, this.logger)

        @Suppress("UNCHECKED_CAST")
        val identityServiceConfig =
            config?.opt(CONFIG_NAMESPACE_IDENTITY_SERVICE) as JSONObject?
                ?: configManager.getConfigSet(CONFIG_NAMESPACE_IDENTITY_SERVICE)

        require(identityServiceConfig != null) { "Identity service configuration is missing." }

        val bucketConfig = identityServiceConfig[CONFIG_BUCKET]
        val bucket = bucketConfig as String?
        val region = identityServiceConfig[CONFIG_REGION] as String?

        require(bucket != null && region != null) { "region or bucket was null." }

        this.graphQLClient = graphQLClient ?: ApiClientManager.getClient(
            context,
            this.sudoUserClient
        )

        this.s3Client =
            s3Client ?: DefaultS3Client(this.context, this.sudoUserClient, region, bucket)

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

        val keyId = this.sudoUserClient.getSymmetricKeyId()
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

    override fun createSudo(sudo: Sudo, callback: (CreateSudoResult) -> Unit) {
        CoroutineScope(IO).launch {
            try {
                val response = createSudo(sudo)
                callback(CreateSudoResult.Success(response))
            }
            catch(e: Exception){
                callback(CreateSudoResult.Failure(e.toApiException()))
            }
        }
    }

    override suspend fun updateSudo(sudo: Sudo) : Sudo {
        this.logger.info("Updating a Sudo.")

        val sudoId = sudo.id
        require(sudoId != null) { "Sudo ID was null." }

        val keyId = this.sudoUserClient.getSymmetricKeyId()
        require(keyId != null) { "Symmetric key missing." }

        try {
            val secureClaims: MutableList<SecureClaimInput> = mutableListOf()
            val secureS3Objects: MutableList<SecureS3ObjectInput> = mutableListOf()

            for ((name, claim) in sudo.claims) {
                if(claim.visibility === Claim.Visibility.PRIVATE) {
                    when (claim.value) {
                        is Claim.Value.BlobValue -> {
                            val file = File(claim.value.value)
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
                                    Claim.Value.BlobValue(cacheEntry.toURI())
                                )

                                val algorithm =
                                    SymmetricKeyEncryptionAlgorithm.AES_CBC_PKCS7PADDING
                                val encrypted =
                                    this.sudoUserClient.encrypt(
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
                                    this.sudoUserClient,
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
                this.queryCache.add(this.defaultQuery, item)

                return sudo
            } else {
                throw SudoProfileException.FailedException("Mutation succeeded but output was null.")
            }
        } catch (e: Exception) {
            throw e.toFailedExceptionOrThrow()
        }
    }

    override fun updateSudo(sudo: Sudo, callback: (UpdateSudoResult) -> Unit) {
        CoroutineScope(IO).launch {
            try {
                val response = updateSudo(sudo)
                callback(UpdateSudoResult.Success(response))
            }
            catch(e: Exception){
                callback(UpdateSudoResult.Failure(e.toApiException()))
            }
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

    override fun deleteSudo(sudo: Sudo, callback: (ApiResult) -> Unit) {
        CoroutineScope(IO).launch {
            try {
                deleteSudo(sudo)
                callback(ApiResult.Success())
            }
            catch(e: Exception){
                callback(ApiResult.Failure(e.toApiException()))
            }
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

    override fun listSudos(option: ListOption, callback: (ListSudosResult) -> Unit) {
        CoroutineScope(IO).launch {
            try {
                val response = listSudos(option)
                callback(ListSudosResult.Success(response))
            }
            catch(e: Exception){
                callback(ListSudosResult.Failure(e.toApiException()))
            }
        }
    }

    override fun reset() {
        this.logger.info("Resetting client.")

        this.graphQLClient.clearCaches()
        this.blobCache.reset()
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

    override fun getOwnershipProof(
        sudo: Sudo,
        audience: String,
        callback: (GetOwnershipProofResult) -> Unit
    ) {
        CoroutineScope(IO).launch {
            try {
                var response = getOwnershipProof(sudo, audience)
                callback(GetOwnershipProofResult.Success(response))
            }
            catch(e: Exception){
                callback(GetOwnershipProofResult.Failure(e.toApiException()))
            }
        }
    }

    override suspend fun redeem(token: String, type: String) : List<Entitlement> {
        this.logger.info("Redeeming a token.")

        try {
            val input = RedeemTokenInput
                .builder()
                .token(token)
                .type(type)
                .build()

            val mutation = RedeemTokenMutation
                .builder()
                .input(input)
                .build()

            val response = this.graphQLClient.mutate(mutation)
                .enqueue()

            if(response.hasErrors()) {
                throw response.errors().first().toSudoProfileException()
            }

            val output = response.data()?.redeemToken
            if (output != null) {
                return output.map {
                    Entitlement(
                        it.name(),
                        it.value()
                    )
                }
            } else {
                throw SudoProfileException.FailedException("Mutation succeeded but output was null.")
            }
        } catch (e: Exception) {
           throw e.toFailedExceptionOrThrow()
        }
    }

    override fun redeem(token: String, type: String, callback: (RedeemResult) -> Unit) {
        CoroutineScope(IO).launch {
            try {
                var response = redeem(token, type)
                callback(RedeemResult.Success(response))
            }
            catch(e: Exception){
                callback(RedeemResult.Failure(e.toApiException()))
            }
        }
    }

    override fun subscribe(id: String, subscriber: SudoSubscriber) {
        CoroutineScope(IO).launch {
            subscribeAsync(id, SudoSubscriber.ChangeType.CREATE, subscriber)
            subscribeAsync(id, SudoSubscriber.ChangeType.UPDATE, subscriber)
            subscribeAsync(id, SudoSubscriber.ChangeType.DELETE, subscriber)
        }
    }

    override suspend fun subscribeAsync(id: String, subscriber: SudoSubscriber) {
        this.subscribeAsync(id, SudoSubscriber.ChangeType.CREATE, subscriber)
        this.subscribeAsync(id, SudoSubscriber.ChangeType.UPDATE, subscriber)
        this.subscribeAsync(id, SudoSubscriber.ChangeType.DELETE, subscriber)
    }

    override fun subscribe(
        id: String,
        changeType: SudoSubscriber.ChangeType,
        subscriber: SudoSubscriber
    ) {
        CoroutineScope(IO).launch {
            subscribeAsync(id, changeType, subscriber)
        }
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

    override fun unsubscribeAll() {
        this.logger.info("Unsubscribing all subscribers from Sudo change notification.")

        this.onCreateSudoSubscriptionManager.removeAllSubscribers()
        this.onUpdateSudoSubscriptionManager.removeAllSubscribers()
        this.onDeleteSudoSubscriptionManager.removeAllSubscribers()
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
        client: SudoUserClient,
        name: String,
        value: String
    ): SecureClaimInput {
        val keyId = client.getSymmetricKeyId()

        if (keyId != null) {
            val algorithm = SymmetricKeyEncryptionAlgorithm.AES_CBC_PKCS7PADDING
            val encryptedData = this.sudoUserClient.encrypt(
                keyId,
                algorithm,
                value.toByteArray()
            )

            return SecureClaimInput
                .builder()
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
        client: SudoUserClient,
        name: String,
        keyId: String,
        algorithm: String,
        base64Data: String
    ): Claim {
        val algorithmSpec =
            SymmetricKeyEncryptionAlgorithm.fromString(algorithm)

        if (algorithmSpec != null) {
            val value = String(
                client.decrypt(
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
                                this.s3Client.delete(cacheEntry.id)
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
                        this.sudoUserClient,
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
                                        Claim.Value.BlobValue(entry.toURI())
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
                                this.sudoUserClient.decrypt(
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
                                    Claim.Value.BlobValue(entry.toURI())
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