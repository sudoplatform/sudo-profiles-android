/*
 * Copyright © 2022 Anonyome Labs, Inc. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package com.sudoplatform.sudoprofiles

import java.io.Serializable

/**
 * Represents an entitlement related to using Sudo service APIs. Currently only entitlement that's used
 * in Sudo service is "sudoplatform.sudo.max" to represent the maximum number of Sudos each user
 * is allowed to provision.
 *
 * @property name [String] entitlement name, e.g "sudoplatform.sudo.max" for maximum number of Sudos.
 * @property value [Int] entitlement value.
 */
data class Entitlement(
    val name: String,
    val value: Int
) : Serializable
