/**
 * Copyright © 2020 Anonyome Labs, Inc. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package com.sudoplatform.sudoprofiles

import java.io.File
import java.io.FileOutputStream
import java.net.URI

/**
 * Simple blob cache implementation that uses the file store.
 *
 * @param containerURI cache container URI.
 * @param idGenerator UUID generator. Mainly used for unit testing.
 */
class BlobCache(containerURI: URI,
                private val idGenerator: IdGenerator = DefaultIdGenerator()) {

    /**
     * Cache entry.
     *
     * @param containerURL cache container URI.
     * @param id entry ID.
     */
    data class Entry(val containerURL: URI, val id: String) {

        /**
         * Returns the URI representation of this entry.
         *
         * @return URI representation of this entry.
         */
        fun toURI(): URI {
            return URI("${this.containerURL}/${this.id}").normalize()
        }

        /**
         * Loads the cache entry from the file store.
         *
         * @return blob as `ByteArray`.
         */
        fun load(): ByteArray {
            val file = File(this.toURI())
            return file.readBytes()
        }

    }

    /**
     * Cache container URI.
     */
    private val containerURI: URI = containerURI.normalize()

    /**
     * Adds a blob located at a specified URI to the cache.
     *
     * @param fileURI Blob URI.
     * @return newly created cache entry.
     */
    fun add(fileURI: URI): Entry {
        val file = File(fileURI)

        val id = this.idGenerator.generateId()
        val newFile = File("${this.containerURI.path}/$id")

        file.copyTo(newFile)

        return Entry(this.containerURI, id)
    }

    /**
     * Adds a blob to the cache.
     *
     * @param data blob as [ByteArray].
     * @return newly created cache entry.
     */
    fun add(data: ByteArray): Entry {
        val id = this.idGenerator.generateId()
        val file = File("${this.containerURI.path}/$id")
        val fos = FileOutputStream(file, false)
        fos.write(data)
        return Entry(this.containerURI, id)
    }

    /**
     * Removes a cache entry.
     *
     * @param id cache entry ID.
     */
    fun remove(id: String) {
        val file = File("${this.containerURI.path}/$id")
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
        val file = File("${this.containerURI.path}/$id")

        val parent = File(file.parent)
        if (!parent.exists()) {
            parent.mkdirs()
        }

        val fos = FileOutputStream(file, false)
        fos.write(data)
        return Entry(this.containerURI, id)
    }

    /**
     * Retrieves a cache entry.
     *
     * @param id cache entry ID.
     * @return cache entry.
     */
    fun get(id: String): Entry? {
        var entry: Entry? = null
        val file = File("${this.containerURI.path}/$id")
        if (file.exists()) {
            entry = Entry(this.containerURI, id)
        }
        return entry
    }

    /**
     * Retrieves a cache entry.
     *
     * @param uri cache entry URI.
     * @return cache entry.
     */
    fun get(uri: URI): Entry? {
        var entry: Entry? = null
        if (uri.path.startsWith(this.containerURI.path)) {
            val file = File(uri)
            if (file.exists()) {
                entry = Entry(this.containerURI, file.name)
            }
        }
        return entry
    }

    /**
     * Removes all entries from the cache.
     */
    fun reset() {
        val files = File(this.containerURI).listFiles()
        for (file in files) {
            file.deleteRecursively()
        }
    }

    /**
     * Returns the number of entries in the cache.
     *
     * @return number of entries in the cache.
     */
    fun count(): Int {
        return File(this.containerURI).listFiles().size
    }

}