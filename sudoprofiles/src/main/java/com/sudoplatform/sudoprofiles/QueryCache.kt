/**
 * Copyright © 2020 Anonyome Labs, Inc. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package com.sudoplatform.sudoprofiles

import com.amazonaws.mobileconnectors.appsync.AWSAppSyncClient
import com.amazonaws.mobileconnectors.appsync.fetcher.AppSyncResponseFetchers
import com.apollographql.apollo.GraphQLCall
import com.apollographql.apollo.api.Response
import com.apollographql.apollo.exception.ApolloException
import kotlin.coroutines.resume
import kotlin.coroutines.suspendCoroutine

/**
 * Wrapper interface for GraphQL client cache operations.
 */
interface QueryCache {

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
     * Adds a new item to the AppSync's query cache.
     *
     * @param query query to update.
     * @param item a new item to add to the cache.
     * @return API result.
     */
    suspend fun add(query: ListSudosQuery, item: ListSudosQuery.Item): ApiResult

}

/**
 * Default query cache implementation.
 *
 * @param graphQLClient AppSync client holding the query cache.
 */
class DefaultQueryCache(private val graphQLClient: AWSAppSyncClient): QueryCache {

    override suspend fun add(query: ListSudosQuery, item: ListSudosQuery.Item): QueryCache.ApiResult = suspendCoroutine { cont ->
        this.graphQLClient.query(query)
            .responseFetcher(AppSyncResponseFetchers.CACHE_ONLY)
            .enqueue(object : GraphQLCall.Callback<ListSudosQuery.Data>() {
                override fun onResponse(response: Response<ListSudosQuery.Data>) {
                    val items: MutableList<ListSudosQuery.Item> = mutableListOf()

                    val existingItems = response.data()?.listSudos()?.items()
                    if (existingItems != null) {
                        items.addAll(existingItems)
                    }

                    items.add(item)

                    val data =
                        ListSudosQuery.Data(
                            ListSudosQuery.ListSudos(
                                "ModelSudoConnection",
                                items,
                                null
                            )
                        )

                    // Currently `GraphQLStoreOperation.Callback` is not public so we have to assume the cache update succeeds and completes
                    // quickly.
                    this@DefaultQueryCache.graphQLClient.store.write(
                        query,
                        data
                    ).enqueue(null)

                    cont.resume(QueryCache.ApiResult.Success())
                }

                override fun onFailure(e: ApolloException) {
                    cont.resume(QueryCache.ApiResult.Failure(e))
                }
            })
    }

}