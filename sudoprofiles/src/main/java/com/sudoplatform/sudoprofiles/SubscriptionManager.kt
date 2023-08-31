/*
 * Copyright © 2022 Anonyome Labs, Inc. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package com.sudoplatform.sudoprofiles

import com.amazonaws.mobileconnectors.appsync.AppSyncSubscriptionCall

/**
 * Manages subscriptions for a specific GraphQL subscription.
 */
internal class SubscriptionManager<T> {

    /**
     * Subscribers.
     */
    internal val subscribers: MutableMap<String, SudoSubscriber> = mutableMapOf()

    /**
     * AppSync subscription watcher.
     */
    internal var watcher: AppSyncSubscriptionCall<T>? = null

    /**
     * Watcher that has not been fully initialized yet. We need to make this
     * distinction because there's a bug in AWSAppSync SDK that causes a crash
     * when a partially initialized watcher is used. This can happen if the
     * subscription creation fails due to a network error. Although the watcher
     * is valid in this situation, it's possible that some internal state is
     * yet to be set by the time the control is returned to the consumer via a
     * callback. We will remove this once AWS has fixed the issue. We are using
     * a separate variable to make the removal easier in the future.
     */
    internal var pendingWatcher: AppSyncSubscriptionCall<T>? = null

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
                if (watcher?.isCanceled == false) {
                    this.watcher?.cancel()
                }
                this.watcher = null
                this.pendingWatcher = null
            }
        }

        // Notify subscribers.
        for (subscriber in subscribersToNotify) {
            subscriber.connectionStatusChanged(state)
        }
    }
}
