/*
 * Copyright © 2022 Anonyome Labs, Inc. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package com.sudoplatform.sudoprofiles.exceptions

sealed class S3Exception(message: String? = null, cause: Throwable? = null) :  SudoProfileException(message, cause) {

    /**
     * Exception thrown when error occurs uploading items to S3 using the TransferListener
     * Example: updateSudo
     */
    class UploadException(message: String? = null, cause: Throwable? = null) :
        S3Exception(message = message, cause = cause)

    /**
     * Exception thrown when error occurs downloading items from S3 using the TransferListener
     * Example: listSudos
     */
    class DownloadException(message: String? = null, cause: Throwable? = null) :
        S3Exception(message = message, cause = cause)
}
