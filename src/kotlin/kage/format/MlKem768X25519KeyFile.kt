/**
 * Copyright 2026 The kage Authors. All rights reserved. Use of this source code is governed by
 * either an Apache 2.0 or MIT license at your discretion, that can be found in the LICENSE-APACHE
 * or LICENSE-MIT files respectively.
 */
package kage.format

import java.io.BufferedReader
import java.io.BufferedWriter
import kage.crypto.mlkem.MlKem768X25519Identity
import kage.crypto.mlkem.MlKem768X25519Identity.Companion.AGE_SECRET_KEY_PQ_PREFIX
import kage.crypto.mlkem.MlKem768X25519Recipient
import kage.crypto.mlkem.MlKem768X25519Recipient.Companion.AGE_PUBLIC_KEY_PQ_PREFIX
import kage.errors.InvalidAgeKeyException
import kage.utils.writeNewLine

/**
 * The contents of an age MLKEM768-X25519 identity file.
 *
 * @property created Value from the file's `created` comment.
 * @property publicKey Public key from the file, if present.
 * @property privateKey Private MLKEM768-X25519 identity from the file.
 */
public class MlKem768X25519KeyFile(
  public val created: String,
  public val publicKey: MlKem768X25519Recipient?,
  public val privateKey: MlKem768X25519Identity,
) {
  override fun equals(other: Any?): Boolean {
    if (other == null) return false
    if (other !is MlKem768X25519KeyFile) return false

    if (this === other) return true

    if (!privateKey.equals(other.privateKey)) return false
    if (publicKey != other.publicKey) return false

    return true
  }

  override fun hashCode(): Int {
    var result = privateKey.hashCode()
    result = 31 * result + (publicKey?.hashCode() ?: 0)
    return result
  }

  internal companion object {

    fun parse(reader: BufferedReader): MlKem768X25519KeyFile {
      val lines = reader.readLines()
      var created = ""
      var publicKeyStr = ""
      var privateKeyStr = ""

      lines.forEach { line ->
        if (line.startsWith("# created: ")) {
          created = parseCreatedLine(line)
        } else if (line.startsWith("# public key: ")) {
          publicKeyStr = parsePublicKeyLine(line)
        } else if (line.startsWith(AGE_SECRET_KEY_PQ_PREFIX)) {
          privateKeyStr = line
        }
      }

      if (privateKeyStr.isEmpty())
        throw InvalidAgeKeyException("Cannot find private key in age key file")

      val privateKey = MlKem768X25519Identity.decode(privateKeyStr)

      val publicKey =
        if (publicKeyStr.isEmpty()) null else MlKem768X25519Recipient.decode(publicKeyStr)

      if (
        publicKey != null && publicKey.encodeToString() != privateKey.recipient().encodeToString()
      ) {
        throw InvalidAgeKeyException("Public key does not match private key")
      }

      return MlKem768X25519KeyFile(created, publicKey, privateKey)
    }

    internal fun write(writer: BufferedWriter, keyFile: MlKem768X25519KeyFile) {
      writer.write("# created: ${keyFile.created}")
      writer.writeNewLine()
      if (keyFile.publicKey != null)
        writer.write("# public key: ${keyFile.publicKey.encodeToString()}")
      writer.writeNewLine()
      writer.write(keyFile.privateKey.encodeToString())
      writer.writeNewLine()
    }

    private fun parseCreatedLine(line: String): String {
      val parts = line.split(": ")
      if (parts.size != 2) throw InvalidAgeKeyException("Invalid created line")
      return parts.last()
    }

    private fun parsePublicKeyLine(line: String): String {
      val parts = line.split(": ")
      if (parts.size != 2) throw InvalidAgeKeyException("Invalid public key line")
      if (!parts.last().startsWith(AGE_PUBLIC_KEY_PQ_PREFIX))
        throw InvalidAgeKeyException("Invalid public key line")
      return parts.last()
    }
  }
}
