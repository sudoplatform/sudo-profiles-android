/*
 * Copyright © 2024 Anonyome Labs, Inc. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package com.sudoplatform.sudoprofiles

/**
 * Subscriber for receiving notifications about new, updated or deleted Sudo.
 */
interface SudoSubscriber {

    /**
     * Sudo change type.
     */
    enum class ChangeType {

        /**
         *  Sudo was created.
         */
        CREATE,

        /**
         * Sudo was updated.
         */
        UPDATE,

        /**
         * Sudo was deleted.
         */
        DELETE,
    }

    /**
     * Connection state of the subscription.
     */
    enum class ConnectionState {

        /**
         * Connected and receiving updates.
         */
        CONNECTED,

        /**
         * Disconnected and won't receive any updates. When disconnected all subscribers will be
         * unsubscribed so the consumer must re-subscribe.
         */
        DISCONNECTED,
    }

    /**
     * Notifies the subscriber of a new, updated or deleted Sudo.
     *
     * @param changeType change type. Please refer to [ChangeType] enum.
     * @param sudo new, updated or deleted Sudo.
     */
    fun sudoChanged(changeType: ChangeType, sudo: Sudo)

    /**
     * Notifies the subscriber that the subscription connection state has changed. The subscriber won't be
     * notified of Sudo changes until the connection status changes to [ConnectionState.CONNECTED]. The subscriber will
     * stop receiving Sudo change notifications when the connection state changes to [ConnectionState.DISCONNECTED].
     * @param state connection state.
     */
    fun connectionStatusChanged(state: ConnectionState)
}
