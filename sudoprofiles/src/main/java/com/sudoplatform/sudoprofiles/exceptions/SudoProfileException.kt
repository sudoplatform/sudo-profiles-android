/*
 * Copyright © 2022 Anonyome Labs, Inc. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package com.sudoplatform.sudoprofiles.exceptions

import com.apollographql.apollo.api.Error
import com.sudoplatform.sudoprofiles.DefaultLogger

open class SudoProfileException(message: String? = null, cause: Throwable? = null) : RuntimeException(message, cause) {

    companion object {
        private const val GRAPHQL_ERROR_TYPE = "errorType"
        private const val GRAPHQL_ERROR_SUDO_NOT_FOUND = "sudoplatform.sudo.SudoNotFound"
        private const val GRAPHQL_ERROR_INSUFFICIENT_ENTITLEMENTS_ERROR = "sudoplatform.InsufficientEntitlementsError"
        private const val GRAPHQL_ERROR_CONDITIONAL_CHECK_FAILED =
            "DynamoDB:ConditionalCheckFailedException"
        private const val GRAPHQL_ERROR_SERVER_ERROR = "sudoplatform.sudo.ServerError"

        /**
        * Convert from a GraphQL [Error] into a custom exception of type [SudoProfileException]
        */
        fun Error.toSudoProfileException(): SudoProfileException {
            val logger = DefaultLogger.instance
            logger.error("GraphQL error received: $this")

            return when (this.customAttributes()[GRAPHQL_ERROR_TYPE]) {
                GRAPHQL_ERROR_SUDO_NOT_FOUND -> SudoNotFoundException(this.message())
                GRAPHQL_ERROR_INSUFFICIENT_ENTITLEMENTS_ERROR -> InsufficientEntitlementsException(this.message())
                GRAPHQL_ERROR_CONDITIONAL_CHECK_FAILED -> VersionMismatchException(this.message())
                GRAPHQL_ERROR_SERVER_ERROR -> InternalServerException(this.message())
                else -> GraphQlException(this.message())
            }
        }
    }

    /**
     * Exception for GraphQl call when Sudo Not Found
     */
    class SudoNotFoundException(message: String? = null, cause: Throwable? = null) :
        SudoProfileException(message = message, cause = cause)

    /**
     * Exception for GraphQl call when insufficient entitlements
     */
    class InsufficientEntitlementsException(message: String? = null, cause: Throwable? = null) :
        SudoProfileException(message = message, cause = cause)

    /**
     * Exception for GraphQl call when there is a Version mismatch.  This can occur if
     * another process has updated a DB entry while you are working on that entry.
     */
    class VersionMismatchException(message: String? = null, cause: Throwable? = null) :
        SudoProfileException(message = message, cause = cause)

    /**
     * Exception for GraphQl call when a `ServerError` is returned
     */
    class InternalServerException(message: String? = null, cause: Throwable? = null) :
        SudoProfileException(message = message, cause = cause)

    /**
     * Exception for GraphQl call when the call itself is successful but there
     * is an Error returned that is unmapped.
     */
    class GraphQlException(message: String? = null, cause: Throwable? = null) :
        SudoProfileException(message = message, cause = cause)

    /**
     * Exception for wrapping exceptions such as `ApolloException` and all other `Exceptions`
     */
    class FailedException(message: String? = null, cause: Throwable? = null) :
        SudoProfileException(message = message, cause = cause)

    /**
     * Exception for when processing secure claim
     */
    class UnsupportedAlgorithmException(message: String? = null, cause: Throwable? = null) :
        SudoProfileException(message = message, cause = cause)

    /**
     * Exception for indicating the configuration related to Sudo Service is not found.
     * This may indicate that Sudo Service is not deployed into your runtime instance or the config
     * file that you are using is invalid..
     */
    class SudoServiceConfigNotFoundException(message: String? = null, cause: Throwable? = null) :
        SudoProfileException(message = message, cause = cause)

    /**
     * Exception for indicating the configuration of the client was invalid.
     */
    class InvalidConfigException(message: String? = null, cause: Throwable? = null) :
        SudoProfileException(message = message, cause = cause)
}
