/*
 * Copyright © 2022 Anonyome Labs, Inc. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package com.sudoplatform.sudoprofiles

import android.net.Uri
import java.io.Serializable
import java.util.Date

/**
 * Represents a claim or identity attribute associated with a Sudo.
 * @property name [String] Claim name.
 * @property visibility [Visibility] Claim visibility.
 * @property value [Value] Claim value.
 */
data class Claim(
    val name: String,
    val visibility: Visibility,
    val value: Value,
) : Serializable {

    /**
     * Claim value.
     */
    sealed class Value : Serializable {
        /**
         * String value.
         */
        data class StringValue(val value: String) : Value()

        /**
         * Blob value represented as a Uri. Typically a file location of the blob.
         *
         */
        data class BlobValue(val value: Uri) : Value()

        /**
         * Returns the unwrapped raw claim value.
         *
         * @return raw claim value.
         */
        fun toRaw(): Any {
            return when (this) {
                is StringValue -> this.value
                is BlobValue -> this.value
            }
        }
    }

    /**
     * Claim visibility.
     */
    enum class Visibility {
        /**
         * Claim is only accessible by the user, i.e. it's encrypted using the user's key.
         */
        PRIVATE,

        /**
         * Claim is accessible by other users in Sudo platform.
         */
        PUBLIC,
    }
}

/**
 * Represents a Sudo.
 *
 * @param id globally unique identifier of this Sudo. This is generated and set by Sudo service.
 * @param version current version of this Sudo.
 * @param createdAt date and time at which this Sudo was created.
 * @param updatedAt date and time at which this Sudo was last updated.
 * @param claims claims.
 * @param metadata arbitrary metadata set by the backend..
 */
data class Sudo(
    var id: String? = null,
    var version: Int = 1,
    var createdAt: Date = Date(0),
    var updatedAt: Date = Date(0),
    var claims: MutableMap<String, Claim> = mutableMapOf(),
    var metadata: MutableMap<String, String> = mutableMapOf(),
) : Serializable {

    companion object {
        private const val TITLE = "title"
        private const val FIRST_NAME = "firstName"
        private const val LAST_NAME = "lastName"
        private const val LABEL = "label"
        private const val NOTES = "notes"
        private const val AVATAR = "avatar"
        private const val EXTERNAL_ID = "ExternalId"
    }

    /**
     * Title.
     */
    var title: String?
        get() = this.claims[TITLE]?.value?.toRaw() as? String
        set(value) {
            if (value != null) {
                val claim = Claim(TITLE, Claim.Visibility.PRIVATE, Claim.Value.StringValue(value))
                this.claims[TITLE] = claim
            }
        }

    /**
     * First name.
     */
    var firstName: String?
        get() = this.claims[FIRST_NAME]?.value?.toRaw() as? String
        set(value) {
            if (value != null) {
                val claim = Claim(FIRST_NAME, Claim.Visibility.PRIVATE, Claim.Value.StringValue(value))
                this.claims[FIRST_NAME] = claim
            }
        }

    /**
     * Last name.
     */
    var lastName: String?
        get() = this.claims[LAST_NAME]?.value?.toRaw() as? String
        set(value) {
            if (value != null) {
                val claim = Claim(LAST_NAME, Claim.Visibility.PRIVATE, Claim.Value.StringValue(value))
                this.claims[LAST_NAME] = claim
            }
        }

    /**
     * Label.
     */
    var label: String?
        get() = this.claims[LABEL]?.value?.toRaw() as? String
        set(value) {
            if (value != null) {
                val claim = Claim(LABEL, Claim.Visibility.PRIVATE, Claim.Value.StringValue(value))
                this.claims[LABEL] = claim
            }
        }

    /**
     * Notes.
     */
    var notes: String?
        get() = this.claims[NOTES]?.value?.toRaw() as? String
        set(value) {
            if (value != null) {
                val claim = Claim(NOTES, Claim.Visibility.PRIVATE, Claim.Value.StringValue(value))
                this.claims[NOTES] = claim
            }
        }

    /**
     * Avatar image URI.
     */
    var avatar: Uri?
        get() = this.claims[AVATAR]?.value?.toRaw() as? Uri
        set(value) {
            if (value != null) {
                val claim = Claim(AVATAR, Claim.Visibility.PRIVATE, Claim.Value.BlobValue(value))
                this.claims[AVATAR] = claim
            }
        }

    /**
     * External ID associated with this Sudo.
     */
    val externalId: String?
        get() = this.metadata[EXTERNAL_ID]

    /**
     * Instantiates a Sudo.
     *
     * @param title title.
     * @param firstName first name.
     * @param lastName last name.
     * @param label label.
     * @param notes notes.
     * @param avatar avatar image URI.
     */
    constructor(title: String?, firstName: String?, lastName: String?, label: String?, notes: String?, avatar: Uri?) : this() {
        this.title = title
        this.firstName = firstName
        this.lastName = lastName
        this.label = label
        this.notes = notes
        this.avatar = avatar
    }
}
