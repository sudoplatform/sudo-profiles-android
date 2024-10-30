/*
 * Copyright © 2024 Anonyome Labs, Inc. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package com.sudoplatform.sudoprofiles

import android.content.Context
import com.amazonaws.auth.CognitoCredentialsProvider
import com.amazonaws.mobileconnectors.s3.transferutility.TransferListener
import com.amazonaws.mobileconnectors.s3.transferutility.TransferState
import com.amazonaws.mobileconnectors.s3.transferutility.TransferUtility
import com.amazonaws.regions.Region
import com.amazonaws.services.s3.AmazonS3Client
import com.amazonaws.services.s3.model.DeleteObjectRequest
import com.sudoplatform.sudologging.Logger
import com.sudoplatform.sudoprofiles.exceptions.S3Exception
import com.sudoplatform.sudouser.SudoUserClient
import kotlinx.coroutines.suspendCancellableCoroutine
import java.io.File
import java.io.FileOutputStream
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException

/**
 * S3 client wrapper protocol mainly used for providing an abstraction layer on top of
 * AWS S3 SDK.
 */
interface S3Client {

    /**
     * AWS region hosting the S3 bucket.
     */
    val region: String

    /**
     * S3 bucket used by Sudo service for storing users' blobs.
     */
    val bucket: String

    /**
     * Uploads a blob to AWS S3.
     *
     * @param data blob as [ByteArray].
     * @param objectId Unique ID for the blob.
     * @return AWS S3 key representing the location of the blob.
     */
    @Throws(S3Exception::class)
    suspend fun upload(data: ByteArray, objectId: String): String

    /**
     * Downloads a blob from AWS S3.
     *
     * @param key AWS S3 key representing the location of the blob.
     */
    @Throws(S3Exception::class)
    suspend fun download(key: String): ByteArray

    /**
     * Deletes a blob from AWS S3.
     *
     * @param objectId AWS S3 key representing the location of the blob.
     */
    suspend fun delete(objectId: String)
}

/**
 * Default S3 client implementation.
 *
 * @param context Android app context.
 * @param sudoUserClient [com.sudoplatform.sudouser.SudoUserClient] used for authenticating to AWS S3.
 */
class DefaultS3Client(
    context: Context,
    sudoUserClient: SudoUserClient,
    override val region: String,
    override val bucket: String,
    private val logger: Logger = DefaultLogger.instance,
    private val idGenerator: IdGenerator = DefaultIdGenerator(),
) : S3Client {

    private val transferUtility: TransferUtility

    private val amazonS3Client: AmazonS3Client

    private val credentialsProvider: CognitoCredentialsProvider = sudoUserClient.getCredentialsProvider()

    init {
        this.amazonS3Client = AmazonS3Client(this.credentialsProvider, Region.getRegion(region))
        this.transferUtility = TransferUtility.builder()
            .context(context)
            .s3Client(this.amazonS3Client)
            .defaultBucket(bucket)
            .build()
    }

    override suspend fun upload(data: ByteArray, objectId: String): String = suspendCancellableCoroutine { cont ->
        this.logger.info("Uploading a blob to S3.")

        val identityId = this.credentialsProvider.identityId
        val key = "$identityId/$objectId"

        val file = File(objectId)
        val tmpFile = File.createTempFile(file.name, ".tmp")
        FileOutputStream(tmpFile).use { it.write(data) }

        val observer = transferUtility.upload(key, tmpFile)
        observer.setTransferListener(object : TransferListener {
            override fun onStateChanged(id: Int, state: TransferState?) {
                when (state) {
                    TransferState.COMPLETED -> {
                        this@DefaultS3Client.logger.info("S3 upload completed successfully.")
                        if (cont.isActive) {
                            cont.resume(key)
                        }
                    }
                    TransferState.CANCELED -> {
                        this@DefaultS3Client.logger.error("S3 upload was cancelled.")
                        if (cont.isActive) {
                            cont.resumeWithException(S3Exception.UploadException("Upload was cancelled."))
                        }
                    }
                    TransferState.FAILED -> {
                        this@DefaultS3Client.logger.error("S3 upload failed.")
                        if (cont.isActive) {
                            cont.resumeWithException(S3Exception.UploadException("Upload failed."))
                        }
                    }
                    else -> this@DefaultS3Client.logger.info("S3 upload state changed: $state.")
                }
            }

            override fun onProgressChanged(id: Int, bytesCurrent: Long, bytesTotal: Long) {
                this@DefaultS3Client.logger.debug("S3 upload progress changed: id=$id, bytesCurrent=$bytesCurrent, bytesTotal=$bytesTotal")
            }

            override fun onError(id: Int, e: Exception?) {
                if (cont.isActive) {
                    cont.resumeWithException(S3Exception.UploadException(e?.message, cause = e))
                }
            }
        })
    }

    override suspend fun download(key: String): ByteArray = suspendCancellableCoroutine { cont ->
        this.logger.info("Downloading a blob from S3.")

        val id = this.idGenerator.generateId()
        val tmpFile = File.createTempFile(id, ".tmp")
        val observer = transferUtility.download(this.bucket, key, tmpFile)
        observer.setTransferListener(object : TransferListener {
            override fun onStateChanged(id: Int, state: TransferState?) {
                when (state) {
                    TransferState.COMPLETED -> {
                        this@DefaultS3Client.logger.info("S3 download completed successfully.")
                        if (cont.isActive) {
                            cont.resume(tmpFile.readBytes())
                        }
                    }
                    TransferState.CANCELED -> {
                        this@DefaultS3Client.logger.error("S3 download was cancelled.")
                        if (cont.isActive) {
                            cont.resumeWithException(S3Exception.DownloadException("Download was cancelled."))
                        }
                    }
                    TransferState.FAILED -> {
                        this@DefaultS3Client.logger.error("S3 download failed.")
                        if (cont.isActive) {
                            cont.resumeWithException(S3Exception.DownloadException("Download failed."))
                        }
                    }
                    else -> this@DefaultS3Client.logger.info("S3 download state changed: $state.")
                }
            }

            override fun onProgressChanged(id: Int, bytesCurrent: Long, bytesTotal: Long) {
                this@DefaultS3Client.logger.debug(
                    "S3 download progress changed: id=$id, bytesCurrent=$bytesCurrent, bytesTotal=$bytesTotal",
                )
            }

            override fun onError(id: Int, e: Exception?) {
                if (cont.isActive) {
                    cont.resumeWithException(S3Exception.DownloadException(e?.message, cause = e))
                }
            }
        })
    }

    override suspend fun delete(objectId: String) {
        this.logger.info("Deleting a blob from S3.")

        val identityId = this.credentialsProvider.identityId
        val key = "$identityId/$objectId"
        val request = DeleteObjectRequest(this.bucket, key)
        this.amazonS3Client.deleteObject(request)
    }
}
