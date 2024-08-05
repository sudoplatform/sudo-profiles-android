/*
 * Copyright © 2024 Anonyome Labs, Inc. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package com.sudoplatform.sudoprofiles

import android.net.Uri
import androidx.core.net.toFile
import java.io.File
import java.io.FileOutputStream

/**
 * Simple blob cache implementation that uses the file store.
 *
 * @param containerUri cache container Uri.
 * @param idGenerator UUID generator. Mainly used for unit testing.
 */
class BlobCache(
    containerUri: Uri,
    private val idGenerator: IdGenerator = DefaultIdGenerator(),
) {

    /**
     * Cache entry.
     *
     * @param containerURL cache container Uri.
     * @param id entry ID.
     */
    data class Entry(val containerURL: Uri, val id: String) {

        /**
         * Returns the Uri representation of this entry.
         *
         * @return Uri representation of this entry.
         */
        fun toUri(): Uri {
            return Uri.parse("${this.containerURL}/${this.id}").normalizeScheme()
        }

        /**
         * Loads the cache entry from the file store.
         *
         * @return blob as `ByteArray`.
         */
        fun load(): ByteArray {
            val file = this.toUri().normalizeScheme().toFile()
            return file.readBytes()
        }
    }

    /**
     * Cache container URI.
     */
    private val containerUri: Uri = containerUri

    /**
     * Adds a blob located at a specified Uri to the cache.
     *
     * @param fileUri Blob Uri.
     * @return newly created cache entry.
     */
    fun add(fileUri: Uri): Entry {
        val file = fileUri.normalizeScheme().toFile()

        val id = this.idGenerator.generateId()
        val newFile = File("${this.containerUri.path}/$id")

        file.copyTo(newFile)

        return Entry(this.containerUri, id)
    }

    /**
     * Adds a blob to the cache.
     *
     * @param data blob as [ByteArray].
     * @return newly created cache entry.
     */
    fun add(data: ByteArray): Entry {
        val id = this.idGenerator.generateId()
        val file = File("${this.containerUri.path}/$id")
        val fos = FileOutputStream(file, false)
        fos.write(data)
        return Entry(this.containerUri, id)
    }

    /**
     * Removes a cache entry.
     *
     * @param id cache entry ID.
     */
    fun remove(id: String) {
        val file = File("${this.containerUri.path}/$id")
        file.delete()
    }

    /**
     * Replaces a cache entry with the specified blob.
     *
     * @param data blob as [ByteArray].
     * @param id cache entry ID.
     * @return updated cache entry.
     */
    fun replace(data: ByteArray, id: String): Entry {
        val file = File("${this.containerUri.path}/$id")
        val parent = File(file.parent!!) // Must have a parent per construction
        if (!parent.exists()) {
            parent.mkdirs()
        }

        val fos = FileOutputStream(file, false)
        fos.write(data)
        return Entry(this.containerUri, id)
    }

    /**
     * Retrieves a cache entry.
     *
     * @param id cache entry ID.
     * @return cache entry.
     */
    fun get(id: String): Entry? {
        var entry: Entry? = null
        val file = File("${this.containerUri.path}/$id")
        if (file.exists()) {
            entry = Entry(this.containerUri, id)
        }
        return entry
    }

    /**
     * Retrieves a cache entry.
     *
     * @param uri cache entry Uri.
     * @return cache entry.
     */
    fun get(uri: Uri): Entry? {
        var entry: Entry? = null
        val uriPath = uri.path
        val containerUriPath = containerUri.path
        if (uriPath != null && containerUriPath != null && uriPath.startsWith(containerUriPath)) {
            val file = uri.normalizeScheme().toFile()
            if (file.exists()) {
                entry = Entry(this.containerUri, file.name)
            }
        }
        return entry
    }

    /**
     * Removes all entries from the cache.
     */
    fun reset() {
        val files = this.containerUri.normalizeScheme().toFile().listFiles()
        if (files != null) {
            for (file in files) {
                file.deleteRecursively()
            }
        }
    }

    /**
     * Returns the number of entries in the cache.
     *
     * @return number of entries in the cache.
     */
    fun count(): Int {
        return this.containerUri.normalizeScheme().toFile().listFiles()?.size ?: 0
    }
}
