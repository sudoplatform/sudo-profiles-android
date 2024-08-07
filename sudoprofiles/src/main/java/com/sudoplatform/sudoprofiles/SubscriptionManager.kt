/*
 * Copyright © 2024 Anonyome Labs, Inc. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package com.sudoplatform.sudoprofiles

import com.amplifyframework.api.graphql.GraphQLOperation

/**
 * Manages subscriptions for a specific GraphQL subscription.
 */
internal class SubscriptionManager<T> {

    /**
     * Subscribers.
     */
    internal val subscribers: MutableMap<String, SudoSubscriber> = mutableMapOf()

    /**
     * Amplify appsync subscription watcher.
     */
    internal var watcher: GraphQLOperation<T>? = null

    /**
     * Adds or replaces a subscriber with the specified ID.
     *
     * @param id subscriber ID.
     * @param subscriber subscriber to subscribe.
     */
    internal fun replaceSubscriber(id: String, subscriber: SudoSubscriber) {
        synchronized(this) {
            this.subscribers[id] = subscriber
        }
    }

    /**
     * Removes the subscriber with the specified ID.
     *
     * @param id subscriber ID.
     */
    internal fun removeSubscriber(id: String) {
        synchronized(this) {
            this.subscribers.remove(id)

            if (this.subscribers.isEmpty()) {
                this.watcher?.cancel()
                this.watcher = null
            }
        }
    }

    /**
     * Removes all subscribers.
     */
    internal fun removeAllSubscribers() {
        synchronized(this) {
            this.subscribers.clear()
            this.watcher?.cancel()
            this.watcher = null
        }
    }

    /**
     * Notifies  subscribers of a new, updated or deleted Sudo.
     *
     * @param changeType change type. Please refer to [SudoSubscriber.ChangeType].
     * @param sudo new, updated or deleted Sudo.
     */
    internal fun sudoChanged(changeType: SudoSubscriber.ChangeType, sudo: Sudo) {
        var subscribersToNotify: ArrayList<SudoSubscriber>
        synchronized(this) {
            // Take a copy of the subscribers to notify in synchronized block
            // but notify outside the block to avoid deadlock.
            subscribersToNotify = ArrayList(this.subscribers.values)
        }

        // Notify subscribers.
        for (subscriber in subscribersToNotify) {
            subscriber.sudoChanged(changeType, sudo)
        }
    }

    /**
     * Processes AppSync subscription connection status change.
     *
     * @param state connection state.
     */
    internal fun connectionStatusChanged(state: SudoSubscriber.ConnectionState) {
        var subscribersToNotify: ArrayList<SudoSubscriber>
        synchronized(this) {
            // Take a copy of the subscribers to notify in synchronized block
            // but notify outside the block to avoid deadlock.
            subscribersToNotify = ArrayList(this.subscribers.values)

            // If the subscription was disconnected then remove all subscribers.
            if (state == SudoSubscriber.ConnectionState.DISCONNECTED) {
                this.subscribers.clear()
                if (this.watcher != null) {
                    this.watcher?.cancel()
                }
                this.watcher = null
            }
        }

        // Notify subscribers.
        for (subscriber in subscribersToNotify) {
            subscriber.connectionStatusChanged(state)
        }
    }
}
