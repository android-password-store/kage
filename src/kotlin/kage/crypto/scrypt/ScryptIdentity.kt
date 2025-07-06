/**
 * Copyright 2022 The kage Authors. All rights reserved. Use of this source code is governed by
 * either an Apache 2.0 or MIT license at your discretion, that can be found in the LICENSE-APACHE
 * or LICENSE-MIT files respectively.
 */
package kage.crypto.scrypt

import kage.Age
import kage.Identity
import kage.crypto.stream.ChaCha20Poly1305
import kage.crypto.stream.ChaCha20Poly1305.KEY_LENGTH
import kage.errors.IncorrectIdentityException
import kage.errors.ScryptIdentityException
import kage.format.AgeStanza
import kage.multiUnwrap
import kage.utils.decodeBase64
import org.bouncycastle.crypto.generators.SCrypt

public class ScryptIdentity(
  private val password: ByteArray,
  private val maxWorkFactor: Int = DEFAULT_WORK_FACTOR,
) : Identity {

  init {
    require(maxWorkFactor in 2..30) { "workFactor must be > 1 and <= 30" }
  }

  override fun unwrap(stanzas: List<AgeStanza>): ByteArray {
    return multiUnwrap(::unwrapSingle, stanzas)
  }

  private fun unwrapSingle(stanza: AgeStanza): ByteArray {
    if (stanza.type != ScryptRecipient.SCRYPT_STANZA_TYPE) throw IncorrectIdentityException()

    if (stanza.args.size != 2) throw ScryptIdentityException("invalid scrypt recipient block")

    val salt =
      try {
        stanza.args.first().decodeBase64()
      } catch (err: IllegalAccessException) {
        throw ScryptIdentityException("failed to parse scrypt salt: ${err.message}")
      }

    if (salt.size != ScryptRecipient.SCRYPT_SALT_SIZE)
      throw ScryptIdentityException("invalid scrypt recipient block")

    val digitsRe = "^[1-9][0-9]*$".toRegex()
    if (!stanza.args[1].matches(digitsRe))
      throw ScryptIdentityException("scrypt work factor encoding invalid: ${stanza.args[1]}")
    val workFactor = stanza.args[1].toInt()

    if (workFactor > maxWorkFactor)
      throw ScryptIdentityException("scrypt factor too large: $workFactor")

    val fullSalt = ScryptRecipient.SCRYPT_SALT_LABEL.toByteArray().plus(salt)

    try {
      val wrappingKey = SCrypt.generate(password, fullSalt, 1 shl workFactor, 8, 1, KEY_LENGTH)
      return ChaCha20Poly1305.aeadDecrypt(wrappingKey, stanza.body, Age.FILE_KEY_SIZE)
    } catch (err: Exception) {
      throw ScryptIdentityException(null, err)
    }
  }

  private companion object {
    const val DEFAULT_WORK_FACTOR = 22
  }
}
