/**
 * Copyright 2021 The kage Authors. All rights reserved. Use of this source code is governed by
 * either an Apache 2.0 or MIT license at your discretion, that can be found in the LICENSE-APACHE
 * or LICENSE-MIT files respectively.
 */
package kage.format

import java.io.BufferedReader

public class AgeKey(public val header: AgeHeader, public val body: ByteArray) {

  override fun equals(other: Any?): Boolean {
    if (other == null) return false
    if (other !is AgeKey) return false

    if (this === other) return true

    if (header != other.header) return false
    if (!body.contentEquals(other.body)) return false

    return true
  }

  override fun hashCode(): Int {
    var result = header.hashCode()
    result = 31 * result + body.contentHashCode()
    return result
  }

  internal companion object {
    internal const val VERSION_LINE = "age-encryption.org/v1"
    internal const val RECIPIENT_PREFIX = "->"
    internal const val FOOTER_PREFIX = "---"
    internal const val COLUMNS_PER_LINE = 64
    internal const val BYTES_PER_LINE = COLUMNS_PER_LINE / 4 * 3

    internal fun parse(reader: BufferedReader): AgeKey {
      val header = AgeHeader.parse(reader)
      TODO("We need to parse the body")
    }
  }
}
