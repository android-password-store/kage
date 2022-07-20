/**
 * Copyright 2021 The kage Authors. All rights reserved. Use of this source code is governed by
 * either an Apache 2.0 or MIT license at your discretion, that can be found in the LICENSE-APACHE
 * or LICENSE-MIT files respectively.
 */
package kage.format

import java.io.BufferedReader
import java.io.BufferedWriter
import kage.crypto.x25519.X25519Identity
import kage.crypto.x25519.X25519Recipient
import kage.errors.InvalidAgeKeyException
import kage.utils.writeNewLine

public class AgeKeyFile(
  public val created: String,
  public val publicKey: X25519Recipient?,
  public val privateKey: X25519Identity
) {
  override fun equals(other: Any?): Boolean {
    if (other == null) return false
    if (other !is AgeKeyFile) return false

    if (this === other) return true

    if (!privateKey.equals(other.privateKey)) return false
    if (publicKey?.equals(other.publicKey) != true) return false

    return true
  }

  override fun hashCode(): Int {
    var result = privateKey.hashCode()
    result = 31 * result + publicKey.hashCode()
    return result
  }

  internal companion object {
    internal const val AGE_SECRET_KEY_PREFIX = "AGE-SECRET-KEY-"
    internal const val AGE_PUBLIC_KEY_PREFIX = "age"

    fun parse(reader: BufferedReader): AgeKeyFile {
      val lines = reader.readLines()
      var created = ""
      var publicKeyStr = ""
      var privateKeyStr = ""

      lines.forEach { line ->
        if (line.startsWith("# created: ")) {
          created = parseCreatedLine(line)
        } else if (line.startsWith("# public key: ")) {
          publicKeyStr = parsePublicKeyLine(line)
        } else if (line.startsWith(AGE_SECRET_KEY_PREFIX)) {
          privateKeyStr = line
        }
      }

      if (privateKeyStr.isEmpty())
        throw InvalidAgeKeyException("Cannot find private key in age key file")

      val privateKey = X25519Identity.decode(privateKeyStr)

      val publicKey = if (publicKeyStr.isEmpty()) null else X25519Recipient.decode(publicKeyStr)

      return AgeKeyFile(created, publicKey, privateKey)
    }

    internal fun write(writer: BufferedWriter, ageKeyFile: AgeKeyFile) {
      writer.write("# created: ${ageKeyFile.created}")
      writer.writeNewLine()
      if (ageKeyFile.publicKey != null)
        writer.write("# public key: ${ageKeyFile.publicKey.encodeToString()}")
      writer.writeNewLine()
      writer.write(ageKeyFile.privateKey.encodeToString())
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
