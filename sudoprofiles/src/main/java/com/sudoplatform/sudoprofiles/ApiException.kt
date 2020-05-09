/**
 * Copyright © 2020 Anonyome Labs, Inc. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package com.sudoplatform.sudoprofiles

enum class ApiErrorCode {
    /**
     * Invalid configuration parameters were passed.
     */
    INVALID_CONFIG,

    /**
     * User is not authorized to perform the operation requested.
     */
    NOT_AUTHORIZED,

    /**
     * Sudo being updated or deleted is not found.
     */
    SUDO_NOT_FOUND,

    /**
     * The version of the resource that's being updated or deleted
     * does not match the version stored in the backend.
     */
    VERSION_MISMATCH,

    /**
     * An internal server error cause the API call to fail. The error is
     * possibly transient and retrying at a later time may cause the call
     * to complete successfully.
     */
    SERVER_ERROR,

    /**
     * Indicates the bad data was found in cache or in backend response.
     */
    BAD_DATA,

    /**
     * GraphQL endpoint returned an error.
     */
    GRAPHQL_ERROR,

    /**
     * AWS S3 returned an error.
     */
    S3_ERROR,

    /**
     * Unexpected error encountered. This could be a result of client or backend bug and unlikely to be user
     * recoverable.
     */
    FATAL_ERROR,

    /**
     * The API call failed due to the user having insufficient entitlements.
     */
    POLICY_ERROR

}

/**
 * [SudoProfilesClient] exception with a specific error code and message.
 *
 * @param code error code.
 * @param message error message.
 * @constructor Creates an API exception with the specified code and message.
 */
data class ApiException(val code: ApiErrorCode, override val message: String): Exception(message)
