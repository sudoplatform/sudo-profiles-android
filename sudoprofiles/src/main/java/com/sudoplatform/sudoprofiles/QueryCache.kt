/*
 * Copyright © 2022 Anonyome Labs, Inc. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package com.sudoplatform.sudoprofiles

import com.amazonaws.mobileconnectors.appsync.AWSAppSyncClient
import com.amazonaws.mobileconnectors.appsync.fetcher.AppSyncResponseFetchers
import com.sudoplatform.sudoprofiles.exceptions.SudoProfileException.Companion.toSudoProfileException
import com.sudoplatform.sudoprofiles.extensions.enqueue

/**
 * Wrapper interface for GraphQL client cache operations.
 */
interface QueryCache {
    /**
     * Adds a new item or replace an existing item in AppSync's query cache.
     *
     * @param query query to update.
     * @param item item to add or replace.
     */
    suspend fun replace(query: ListSudosQuery, item: ListSudosQuery.Item)
}

/**
 * Default query cache implementation.
 *
 * @param graphQLClient AppSync client holding the query cache.
 */
class DefaultQueryCache(private val graphQLClient: AWSAppSyncClient) : QueryCache {

    override suspend fun replace(query: ListSudosQuery, item: ListSudosQuery.Item) {
        val sudos = this.graphQLClient.query(query)
            .responseFetcher(AppSyncResponseFetchers.CACHE_ONLY)
            .enqueue()

        if (sudos.hasErrors()) {
            throw sudos.errors().first().toSudoProfileException()
        }

        val items: MutableList<ListSudosQuery.Item> = mutableListOf()

        val existingItems = sudos.data()?.listSudos()?.items()
        if (existingItems != null) {
            items.addAll(existingItems.filter { it.id() != item.id() })
        }

        items.add(item)

        val data =
            ListSudosQuery.Data(
                ListSudosQuery.ListSudos(
                    "ModelSudoConnection",
                    items,
                    null,
                ),
            )

        // Currently `GraphQLStoreOperation.Callback` is not public so we have to assume the cache update succeeds and completes
        // quickly.
        this@DefaultQueryCache.graphQLClient.store.write(
            query,
            data,
        ).enqueue(null)
    }
}
