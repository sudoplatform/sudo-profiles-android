package com.sudoplatform.sudoprofiles.exceptions

import com.apollographql.apollo.api.Error
import com.sudoplatform.sudoprofiles.DefaultLogger

open class SudoProfileException(message: String? = null, cause: Throwable? = null) : RuntimeException(message, cause) {

    companion object {
        private const val GRAPHQL_ERROR_TYPE = "errorType"
        private const val GRAPHQL_ERROR_SUDO_NOT_FOUND = "sudoplatform.sudo.SudoNotFound"
        private const val GRAPHQL_ERROR_POLICY_ERROR = "sudoplatform.PolicyFailed"
        private const val GRAPHQL_ERROR_CONDITIONAL_CHECK_FAILED =
            "DynamoDB:ConditionalCheckFailedException"
        private const val GRAPHQL_ERROR_SERVER_ERROR = "sudoplatform.sudo.ServerError"

        /**
         * Convert from a [SudoProfileException] to a [ApiException] for backwards compatibility
         */
        fun Exception.toApiException(): ApiException {
            return when (this) {
                // GraphQl Exceptions
                is SudoNotFoundException -> ApiException(ApiErrorCode.SUDO_NOT_FOUND, "${this.localizedMessage}")
                is PolicyFailedException -> ApiException(ApiErrorCode.POLICY_ERROR, "${this.localizedMessage}")
                is ConditionalCheckFailedException -> ApiException(ApiErrorCode.VERSION_MISMATCH, "${this.localizedMessage}")
                is InternalServerException -> ApiException(ApiErrorCode.SERVER_ERROR, "${this.localizedMessage ?: "Internal server error occurred."}")
                is GraphQlException -> ApiException(ApiErrorCode.GRAPHQL_ERROR, "${this.localizedMessage}")
                // Other Exceptions
                is S3Exception.UploadException -> ApiException(ApiErrorCode.S3_ERROR, "S3 upload failed: ${this.localizedMessage}")
                is S3Exception.DownloadException -> ApiException(ApiErrorCode.S3_ERROR, "S3 download failed: ${this.localizedMessage}")
                is UnsupportedAlgorithmException -> ApiException(ApiErrorCode.BAD_DATA, "Unsupported algorithm found in secure claim.")
                else -> ApiException(ApiErrorCode.FATAL_ERROR, "${this.localizedMessage}")
            }
        }

        /**
        * Convert from a GraphQL [Error] into a custom exception of type [SudoProfileException]
        */
        fun Error.toSudoProfileException(): SudoProfileException {
            val logger = DefaultLogger.instance
            logger.error("GraphQL error received: $this")

            return when (this.customAttributes()[GRAPHQL_ERROR_TYPE]) {
                GRAPHQL_ERROR_SUDO_NOT_FOUND -> SudoNotFoundException(this.message())
                GRAPHQL_ERROR_POLICY_ERROR -> PolicyFailedException(this.message())
                GRAPHQL_ERROR_CONDITIONAL_CHECK_FAILED -> ConditionalCheckFailedException(this.message())
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
     * Exception for GraphQl call when policy failed
     */
    class PolicyFailedException(message: String? = null, cause: Throwable? = null) :
        SudoProfileException(message = message, cause = cause)

    /**
     * Exception for GraphQl call when there is a Version mismatch.  This can occur if
     * another process has updated a DB entry while you are working on that entry.
     */
    class ConditionalCheckFailedException(message: String? = null, cause: Throwable? = null) :
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

}