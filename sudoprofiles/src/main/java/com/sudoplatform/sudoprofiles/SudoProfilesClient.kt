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
import com.amazonaws.mobileconnectors.appsync.ConflictResolutionFailedException
import com.amazonaws.mobileconnectors.appsync.fetcher.AppSyncResponseFetchers
import com.apollographql.apollo.GraphQLCall
import com.apollographql.apollo.api.Error
import com.apollographql.apollo.api.Response
import com.apollographql.apollo.exception.ApolloException
import com.sudoplatform.sudoapiclient.ApiClientManager
import com.sudoplatform.sudoconfigmanager.DefaultSudoConfigManager
import com.sudoplatform.sudoprofiles.type.*
import com.sudoplatform.sudouser.SudoUserClient
import com.sudoplatform.sudouser.SymmetricKeyEncryptionAlgorithm
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.GlobalScope
import kotlinx.coroutines.launch
import org.json.JSONObject
import java.io.File
import java.net.URI
import java.util.*
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException
import kotlin.coroutines.suspendCoroutine
import com.sudoplatform.sudologging.Logger

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
    fun createSudo(sudo: Sudo, callback: (CreateSudoResult) -> Unit)

    /**
     * Updates a Sudo.
     *
     * @param sudo Sudo to update.
     * @param callback callback for returning Sudo update result or error.
     */
    fun updateSudo(sudo: Sudo, callback: (UpdateSudoResult) -> Unit)

    /**
     * Deletes a Sudo.
     *
     * @param sudo Sudo to delete.
     * @param callback callback for returning Sudo deletion result or error.
     */
    fun deleteSudo(sudo: Sudo, callback: (ApiResult) -> Unit)

    /**
     * Retrieves all Sudos owned by the signed in user.
     *
     * @param option: option for controlling the behaviour of this API. Refer to `ListOption` enum.
     * @param callback callback for returning list Sudos result or error.
     */
    fun listSudos(option: ListOption, callback: (ListSudosResult) -> Unit)

    /**
     * Reset any internal state and cached content.
     */
    fun reset()

    /**
     * Retrieves a signed owernship proof for the specified owner. The ownership proof JWT has the
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
    fun getOwnershipProof(sudo: Sudo, audience: String, callback: (GetOwnershipProofResult) -> Unit)


    /**
     * Redeem a token to be granted additional entitlements.
     *
     * @param token Token.
     * @param type Token type. Currently only valid value is "entitlements" but this maybe extended in future.
     * @param callback callback for returning redeem result or error.
     */
    fun redeem(token: String, type: String, callback: (RedeemResult) -> Unit)

    /**
     * Subscribes to be notified of new, updated or deleted Sudos. Blob data is not downloaded automatically
     * so the caller is expected to use `listSudos` API if they need to access any associated blobs.
     *
     * @param id unique ID for the subscriber.
     * @param changeType change type to subscribe to.
     * @param subscriber subscriber to notify.
     */
    fun subscribe(id: String, changeType: SudoSubscriber.ChangeType, subscriber: SudoSubscriber)

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
class DefaultSudoProfilesClient(
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

        private const val GRAPHQL_ERROR_TYPE = "errorType"
        private const val GRAPHQL_ERROR_SUDO_NOT_FOUND = "sudoplatform.sudo.SudoNotFound"
        private const val GRAPHQL_ERROR_POLICY_ERROR = "sudoplatform.PolicyFailed"
        private const val GRAPHQL_ERROR_CONDITIONAL_CHECK_FAILED =
            "DynamoDB:ConditionalCheckFailedException"
        private const val GRAPHQL_ERROR_SERVER_ERROR = "sudoplatform.sudo.ServerError"
    }

    override val version: String = "1.0"

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

        val bucket = identityServiceConfig[CONFIG_BUCKET] as String?
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

    override fun createSudo(sudo: Sudo, callback: (CreateSudoResult) -> Unit) {
        this.logger.info("Creating a Sudo.")

        val keyId = this.sudoUserClient.getSymmetricKeyId()
        require(keyId != null) { "Symmetric key missing." }

        GlobalScope.launch(Dispatchers.IO) {
            try {
                val input = CreateSudoInput.builder()
                    .claims(listOf())
                    .objects(listOf())
                    .build()

                this@DefaultSudoProfilesClient.graphQLClient.mutate(
                    CreateSudoMutation.builder().input(
                        input
                    ).build()
                )
                    .enqueue(object : GraphQLCall.Callback<CreateSudoMutation.Data>() {
                        override fun onResponse(response: Response<CreateSudoMutation.Data>) {
                            val error = response.errors().firstOrNull()
                            if (error != null) {
                                callback(
                                    CreateSudoResult.Failure(
                                        this@DefaultSudoProfilesClient.graphQLErrorToApiException(
                                            error
                                        )
                                    )
                                )
                            } else {
                                val output = response.data()?.createSudo()
                                if (output != null) {
                                    sudo.id = output.id()
                                    sudo.version = output.version()
                                    sudo.createdAt = Date(output.createdAtEpochMs().toLong())
                                    sudo.updatedAt = Date(output.updatedAtEpochMs().toLong())

                                    this@DefaultSudoProfilesClient.updateSudo(sudo) { result ->
                                        when (result) {
                                            is UpdateSudoResult.Success -> {
                                                callback(
                                                    CreateSudoResult.Success(
                                                        result.sudo
                                                    )
                                                )
                                            }
                                            is UpdateSudoResult.Failure -> {
                                                callback(
                                                    CreateSudoResult.Failure(
                                                        result.error
                                                    )
                                                )
                                            }
                                        }
                                    }
                                } else {
                                    callback(
                                        CreateSudoResult.Failure(
                                            IllegalStateException("Mutation succeeded but output was null.")
                                        )
                                    )
                                }
                            }
                        }

                        override fun onFailure(e: ApolloException) {
                            callback(
                                CreateSudoResult.Failure(e)
                            )
                        }
                    })
            } catch (e: Exception) {
                callback(
                    CreateSudoResult.Failure(e)
                )
            }
        }
    }

    override fun updateSudo(sudo: Sudo, callback: (UpdateSudoResult) -> Unit) {
        this.logger.info("Updating a Sudo.")

        val sudoId = sudo.id
        require(sudoId != null) { "Sudo ID was null." }

        val keyId = this.sudoUserClient.getSymmetricKeyId()
        require(keyId != null) { "Symmetric key missing." }

        GlobalScope.launch(Dispatchers.IO) {
            try {
                val secureClaims: MutableList<SecureClaimInput> = mutableListOf()
                val secureS3Objects: MutableList<SecureS3ObjectInput> = mutableListOf()

                for ((name, claim) in sudo.claims) {
                    when (claim.visibility) {
                        Claim.Visibility.PRIVATE -> {
                            when (claim.value) {
                                is Claim.Value.BlobValue -> {
                                    val file = File(claim.value.value)
                                    val data = file.readBytes()

                                    val cacheEntry =
                                        this@DefaultSudoProfilesClient.blobCache.replace(
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
                                            this@DefaultSudoProfilesClient.sudoUserClient.encrypt(
                                                keyId,
                                                algorithm,
                                                data
                                            )

                                        val key = this@DefaultSudoProfilesClient.s3Client.upload(
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
                                                .bucket(this@DefaultSudoProfilesClient.s3Client.bucket)
                                                .region(this@DefaultSudoProfilesClient.s3Client.region)
                                                .key(key)
                                                .build()
                                        )
                                    } catch (e: Exception) {
                                        this@DefaultSudoProfilesClient.blobCache.remove(cacheEntry.id)
                                        throw e
                                    }
                                }
                                is Claim.Value.StringValue -> {
                                    secureClaims.add(
                                        this@DefaultSudoProfilesClient.createSecureString(
                                            this@DefaultSudoProfilesClient.sudoUserClient,
                                            name,
                                            claim.value.value
                                        )
                                    )
                                }
                            }
                        }
                        else -> {
                            // Currently other visibility types are not supported.
                        }
                    }
                }

                val input = UpdateSudoInput.builder()
                    .id(sudoId)
                    .expectedVersion(sudo.version)
                    .claims(secureClaims)
                    .objects(secureS3Objects)
                    .build()

                this@DefaultSudoProfilesClient.graphQLClient.mutate(
                    UpdateSudoMutation.builder().input(
                        input
                    ).build()
                )
                    .enqueue(object : GraphQLCall.Callback<UpdateSudoMutation.Data>() {
                        override fun onResponse(response: Response<UpdateSudoMutation.Data>) {
                            val error = response.errors().firstOrNull()
                            if (error != null) {
                                callback(
                                    UpdateSudoResult.Failure(
                                        this@DefaultSudoProfilesClient.graphQLErrorToApiException(
                                            error
                                        )
                                    )
                                )
                            } else {
                                val output = response.data()?.updateSudo()
                                if (output != null) {
                                    sudo.id = output.id()
                                    sudo.version = output.version()
                                    sudo.createdAt = Date(output.createdAtEpochMs().toLong())
                                    sudo.updatedAt = Date(output.updatedAtEpochMs().toLong())

                                    GlobalScope.launch(Dispatchers.IO) {
                                        val result =
                                            this@DefaultSudoProfilesClient.queryCache.add(
                                                this@DefaultSudoProfilesClient.defaultQuery,
                                                ListSudosQuery.Item(
                                                    "Sudo",
                                                    output.id,
                                                    output.claims().map {
                                                        ListSudosQuery.Claim(
                                                            "SecureClaim",
                                                            it.name(),
                                                            it.version(),
                                                            it.algorithm(),
                                                            it.keyId(),
                                                            it.base64Data()
                                                        )
                                                    },
                                                    output.objects().map {
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
                                                    output.metadata().map {
                                                        ListSudosQuery.Metadatum(
                                                            "Attribute",
                                                            it.name(),
                                                            it.value()
                                                        )
                                                    },
                                                    output.createdAtEpochMs(),
                                                    output.updatedAtEpochMs(),
                                                    output.version(),
                                                    output.owner()
                                                )
                                            )

                                        when (result) {
                                            is QueryCache.ApiResult.Success -> {
                                                callback(UpdateSudoResult.Success(sudo))
                                            }
                                            is QueryCache.ApiResult.Failure -> {
                                                callback(UpdateSudoResult.Failure(result.error))
                                            }
                                        }
                                    }
                                } else {
                                    callback(
                                        UpdateSudoResult.Failure(
                                            IllegalStateException("Mutation succeeded but output was null.")
                                        )
                                    )
                                }
                            }
                        }

                        override fun onFailure(e: ApolloException) {
                            when (e) {
                                is ConflictResolutionFailedException -> {
                                    callback(
                                        UpdateSudoResult.Failure(
                                            ApiException(
                                                ApiErrorCode.VERSION_MISMATCH,
                                                "$e"
                                            )
                                        )
                                    )
                                }
                                else -> {
                                    callback(
                                        UpdateSudoResult.Failure(e)
                                    )
                                }
                            }
                        }
                    })
            } catch (e: Exception) {
                callback(
                    UpdateSudoResult.Failure(e)
                )
            }
        }
    }

    override fun deleteSudo(sudo: Sudo, callback: (ApiResult) -> Unit) {
        this.logger.info("Deleting a Sudo.")

        val sudoId = sudo.id
        require(
            sudoId != null
        ) { "Sudo ID was null." }

        GlobalScope.launch(Dispatchers.IO) {
            try {
                this@DefaultSudoProfilesClient.deleteSecureS3Objects(sudoId)

                val input =
                    DeleteSudoInput.builder().id(sudoId).expectedVersion(sudo.version).build()
                this@DefaultSudoProfilesClient.graphQLClient.mutate(
                    DeleteSudoMutation.builder().input(
                        input
                    ).build()
                )
                    .enqueue(object : GraphQLCall.Callback<DeleteSudoMutation.Data>() {
                        override fun onResponse(response: Response<DeleteSudoMutation.Data>) {
                            val error = response.errors().firstOrNull()
                            if (error != null) {
                                callback(
                                    ApiResult.Failure(
                                        this@DefaultSudoProfilesClient.graphQLErrorToApiException(
                                            error
                                        )
                                    )
                                )
                            } else {
                                callback(ApiResult.Success())
                            }
                        }

                        override fun onFailure(e: ApolloException) {
                            callback(
                                ApiResult.Failure(e)
                            )
                        }

                    })
            } catch (e: Exception) {
                callback(
                    ApiResult.Failure(e)
                )
            }
        }
    }

    override fun listSudos(option: ListOption, callback: (ListSudosResult) -> Unit) {
        this.logger.info("Listing Sudos.")

        GlobalScope.launch(Dispatchers.IO) {
            val responseFetcher = when (option) {
                ListOption.CACHE_ONLY -> {
                    AppSyncResponseFetchers.CACHE_ONLY
                }
                ListOption.REMOTE_ONLY -> {
                    AppSyncResponseFetchers.NETWORK_ONLY
                }
            }

            val call =
                this@DefaultSudoProfilesClient.graphQLClient.query(this@DefaultSudoProfilesClient.defaultQuery)
                    .responseFetcher(responseFetcher)

            call.enqueue(object : GraphQLCall.Callback<ListSudosQuery.Data>() {
                override fun onResponse(response: Response<ListSudosQuery.Data>) {
                    GlobalScope.launch(Dispatchers.IO) {
                        try {
                            val error = response.errors().firstOrNull()
                            if (error != null) {
                                callback(
                                    ListSudosResult.Failure(
                                        this@DefaultSudoProfilesClient.graphQLErrorToApiException(
                                            error
                                        )
                                    )
                                )
                            } else {
                                var sudos: List<Sudo> = listOf()

                                // Iterate over Sudos.
                                val items = response.data()?.listSudos()?.items()
                                if (items != null) {
                                    sudos = this@DefaultSudoProfilesClient.processListSudos(
                                        items,
                                        option,
                                        true
                                    )
                                }

                                callback(
                                    ListSudosResult.Success(sudos)
                                )
                            }
                        } catch (e: Exception) {
                            callback(
                                ListSudosResult.Failure(e)
                            )
                        }
                    }
                }

                override fun onFailure(e: ApolloException) {
                    callback(
                        ListSudosResult.Failure(e)
                    )
                }
            })
        }
    }

    override fun reset() {
        this.logger.info("Resetting client.")

        this.graphQLClient.clearCaches()
        this.blobCache.reset()
    }

    override fun getOwnershipProof(
        sudo: Sudo,
        audience: String,
        callback: (GetOwnershipProofResult) -> Unit
    ) {
        this.logger.info("Getting a Sudo ownership proof.")

        val sudoId = sudo.id
        require(
            sudoId != null
        ) { "Sudo ID was null." }

        GlobalScope.launch(Dispatchers.IO) {
            try {
                val input =
                    GetOwnershipProofInput.builder().sudoId(sudoId).audience(audience).build()
                this@DefaultSudoProfilesClient.graphQLClient.mutate(
                    GetOwnershipProofMutation.builder().input(
                        input
                    ).build()
                )
                    .enqueue(object : GraphQLCall.Callback<GetOwnershipProofMutation.Data>() {
                        override fun onResponse(response: Response<GetOwnershipProofMutation.Data>) {
                            val error = response.errors().firstOrNull()
                            if (error != null) {
                                callback(
                                    GetOwnershipProofResult.Failure(
                                        this@DefaultSudoProfilesClient.graphQLErrorToApiException(
                                            error
                                        )
                                    )
                                )
                            } else {
                                val output = response.data()?.ownershipProof
                                if (output != null) {
                                    callback(
                                        GetOwnershipProofResult.Success(output.jwt())
                                    )
                                } else {
                                    callback(
                                        GetOwnershipProofResult.Failure(
                                            IllegalStateException("Mutation succeeded but output was null.")
                                        )
                                    )
                                }
                            }
                        }

                        override fun onFailure(e: ApolloException) {
                            callback(
                                GetOwnershipProofResult.Failure(e)
                            )
                        }

                    })
            } catch (e: Exception) {
                callback(
                    GetOwnershipProofResult.Failure(e)
                )
            }
        }
    }

    override fun redeem(token: String, type: String, callback: (RedeemResult) -> Unit) {
        this.logger.info("Redeeming a token.")

        GlobalScope.launch(Dispatchers.IO) {
            try {
                val input =
                    RedeemTokenInput.builder().token(token).type(type).build()
                this@DefaultSudoProfilesClient.graphQLClient.mutate(
                    RedeemTokenMutation.builder().input(
                        input
                    ).build()
                )
                    .enqueue(object : GraphQLCall.Callback<RedeemTokenMutation.Data>() {
                        override fun onResponse(response: Response<RedeemTokenMutation.Data>) {
                            val error = response.errors().firstOrNull()
                            if (error != null) {
                                callback(
                                    RedeemResult.Failure(
                                        this@DefaultSudoProfilesClient.graphQLErrorToApiException(
                                            error
                                        )
                                    )
                                )
                            } else {
                                val output = response.data()?.redeemToken
                                if (output != null) {
                                    callback(
                                        RedeemResult.Success(output.map {
                                            Entitlement(
                                                it.name(),
                                                it.value()
                                            )
                                        })
                                    )
                                } else {
                                    callback(
                                        RedeemResult.Failure(
                                            IllegalStateException("Mutation succeeded but output was null.")
                                        )
                                    )
                                }
                            }
                        }

                        override fun onFailure(e: ApolloException) {
                            callback(
                                RedeemResult.Failure(e)
                            )
                        }

                    })
            } catch (e: Exception) {
                callback(
                    RedeemResult.Failure(e)
                )
            }
        }
    }

    override fun subscribe(
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
                    GlobalScope.launch(Dispatchers.IO) {
                        val subscription = OnCreateSudoSubscription.builder().owner(owner).build()
                        val watcher =
                            this@DefaultSudoProfilesClient.graphQLClient.subscribe(subscription)
                        this@DefaultSudoProfilesClient.onCreateSudoSubscriptionManager.watcher =
                            watcher
                        watcher.execute(
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
                                    GlobalScope.launch(Dispatchers.IO) {
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

                        this@DefaultSudoProfilesClient.onCreateSudoSubscriptionManager.connectionStatusChanged(
                            SudoSubscriber.ConnectionState.CONNECTED
                        )
                    }
                }
            }
            SudoSubscriber.ChangeType.DELETE -> {
                this.onDeleteSudoSubscriptionManager.replaceSubscriber(id, subscriber)
                if (this.onDeleteSudoSubscriptionManager.watcher == null) {
                    GlobalScope.launch(Dispatchers.IO) {
                        val subscription = OnDeleteSudoSubscription.builder().owner(owner).build()
                        val watcher =
                            this@DefaultSudoProfilesClient.graphQLClient.subscribe(subscription)
                        this@DefaultSudoProfilesClient.onDeleteSudoSubscriptionManager.watcher =
                            watcher
                        watcher.execute(
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
                                    GlobalScope.launch(Dispatchers.IO) {
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

                        this@DefaultSudoProfilesClient.onDeleteSudoSubscriptionManager.connectionStatusChanged(
                            SudoSubscriber.ConnectionState.CONNECTED
                        )
                    }
                }
            }
            SudoSubscriber.ChangeType.UPDATE -> {
                this.onUpdateSudoSubscriptionManager.replaceSubscriber(id, subscriber)
                if (this.onUpdateSudoSubscriptionManager.watcher == null) {
                    GlobalScope.launch(Dispatchers.IO) {
                        val subscription = OnUpdateSudoSubscription.builder().owner(owner).build()
                        val watcher =
                            this@DefaultSudoProfilesClient.graphQLClient.subscribe(subscription)
                        this@DefaultSudoProfilesClient.onUpdateSudoSubscriptionManager.watcher =
                            watcher
                        watcher.execute(
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
                                    GlobalScope.launch(Dispatchers.IO) {
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

                        this@DefaultSudoProfilesClient.onUpdateSudoSubscriptionManager.connectionStatusChanged(
                            SudoSubscriber.ConnectionState.CONNECTED
                        )
                    }
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
            throw IllegalStateException("No symmetric key found.")
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
            throw ApiException(
                ApiErrorCode.BAD_DATA,
                "Unsupported algorithm found in secure claim."
            )
        }
    }

    private suspend fun getSudo(id: String): Sudo? = suspendCoroutine { cont ->
        this.listSudos(ListOption.CACHE_ONLY) { result ->
            when (result) {
                is ListSudosResult.Success -> {
                    cont.resume(result.sudos.firstOrNull { it.id == id })

                }
                is ListSudosResult.Failure -> {
                    throw result.error
                }
            }
        }
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

    private fun graphQLErrorToApiException(error: Error): ApiException {
        this.logger.error("GraphQL error received: $error")

        when (error.customAttributes()[GRAPHQL_ERROR_TYPE]) {
            GRAPHQL_ERROR_SUDO_NOT_FOUND -> {
                return ApiException(ApiErrorCode.SUDO_NOT_FOUND, "$error")
            }
            GRAPHQL_ERROR_POLICY_ERROR -> {
                return ApiException(ApiErrorCode.POLICY_ERROR, "$error")
            }
            GRAPHQL_ERROR_CONDITIONAL_CHECK_FAILED -> {
                return ApiException(ApiErrorCode.VERSION_MISMATCH, "$error")
            }
            GRAPHQL_ERROR_SERVER_ERROR -> {
                return ApiException(ApiErrorCode.SERVER_ERROR, "$error")
            }
            else -> {
                return ApiException(ApiErrorCode.GRAPHQL_ERROR, "$error")
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
                            throw ApiException(
                                ApiErrorCode.BAD_DATA,
                                "Unsupported algorithm found in secure S3 object."
                            )
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

    private suspend fun getCachedQueryItems(): List<ListSudosQuery.Item>? =
        suspendCoroutine { cont ->
            val call =
                this.graphQLClient.query(this@DefaultSudoProfilesClient.defaultQuery)
                    .responseFetcher(AppSyncResponseFetchers.CACHE_ONLY)

            call.enqueue(object : GraphQLCall.Callback<ListSudosQuery.Data>() {
                override fun onResponse(response: Response<ListSudosQuery.Data>) {
                    GlobalScope.launch(Dispatchers.IO) {
                        try {
                            val error = response.errors().firstOrNull()
                            if (error != null) {
                                cont.resumeWithException(
                                    ApiException(
                                        ApiErrorCode.FATAL_ERROR,
                                        "Failed to fetch cached query items: $error"
                                    )
                                )
                            } else {
                                cont.resume(response.data()?.listSudos()?.items())
                            }
                        } catch (e: Exception) {
                            cont.resumeWithException(e)
                        }
                    }
                }

                override fun onFailure(e: ApolloException) {
                    cont.resumeWithException(e)
                }
            })
        }

    private fun getS3ObjectIdFromKey(key: String): String? {
        val components = key.split("/")
        return components.lastOrNull()
    }

}