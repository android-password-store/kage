/**
 * Copyright 2021 The kage Authors. All rights reserved. Use of this source code is governed by
 * either an Apache 2.0 or MIT license at your discretion, that can be found in the LICENSE-APACHE
 * or LICENSE-MIT files respectively.
 */
package kage.format

import java.io.BufferedReader
import java.io.BufferedWriter
import kage.errors.InvalidAgeKeyException
import kage.utils.writeNewLine

public class AgeKey(
  public val created: String,
  public val publicKey: ByteArray,
  public val privateKey: ByteArray
) {
  override fun equals(other: Any?): Boolean {
    if (other == null) return false
    if (other !is AgeKey) return false

    if (this === other) return true

    if (!privateKey.contentEquals(other.privateKey)) return false
    if (!publicKey.contentEquals(other.publicKey)) return false

    return true
  }

  override fun hashCode(): Int {
    var result = privateKey.contentHashCode()
    result = 31 * result + publicKey.contentHashCode()
    return result
  }

  internal companion object {
    internal const val AGE_SECRET_KEY_PREFIX = "AGE-SECRET-KEY-"
    internal const val AGE_PUBLIC_KEY_PREFIX = "age"

    fun parse(reader: BufferedReader): AgeKey {
      val lines = reader.readLines()
      var created = ""
      var publicKey = ""
      var privateKey = ""

      lines.forEach { line ->
        if (line.startsWith("# created: ")) {
          created = parseCreatedLine(line)
        } else if (line.startsWith("# public key: ")) {
          publicKey = parsePublicKeyLine(line)
        } else if (line.startsWith(AGE_SECRET_KEY_PREFIX)) {
          privateKey = line
        }
      }

      if (privateKey.isEmpty())
        throw InvalidAgeKeyException("Cannot find private key in age key file")
      return AgeKey(created, publicKey.encodeToByteArray(), privateKey.encodeToByteArray())
    }

    internal fun write(writer: BufferedWriter, ageKey: AgeKey) {
      if (ageKey.privateKey.isEmpty())
        throw InvalidAgeKeyException("Cannot find private key in age key file")
      writer.write("# created: ${ageKey.created}")
      writer.writeNewLine()
      writer.write("# public key: ${ageKey.publicKey.decodeToString()}")
      writer.writeNewLine()
      writer.write(ageKey.privateKey.decodeToString())
      writer.writeNewLine()
    }

    // TODO: Discuss if this method should throw or not
    private fun parseCreatedLine(line: String): String {
      val parts = line.split(": ")
      if (parts.size != 2) throw InvalidAgeKeyException("Invalid created line")
      return parts.last()
    }

    private fun parsePublicKeyLine(line: String): String {
      val parts = line.split(": ")
      if (parts.size != 2) throw InvalidAgeKeyException("Invalid public key line")
      if (!parts.last().startsWith(AGE_PUBLIC_KEY_PREFIX))
        throw InvalidAgeKeyException("Invalid public key line")
      return parts.last()
    }
  }
}
