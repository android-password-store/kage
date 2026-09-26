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

/**
 * An age identity that decrypts files encrypted with the supplied password.
 *
 * @param password Password bytes used to derive the wrapping key.
 * @param maxWorkFactor Largest scrypt work factor accepted while decrypting. The default accepts up
 *   to 256 MiB of scrypt working memory; configure a larger value only when the caller can tolerate
 *   the corresponding resource cost.
 */
public class ScryptIdentity
@JvmOverloads
constructor(
  private val password: ByteArray,
  private val maxWorkFactor: Int = DEFAULT_MAX_WORK_FACTOR,
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
      } catch (err: IllegalArgumentException) {
        throw ScryptIdentityException("failed to parse scrypt salt: ${err.message}")
      }

    if (salt.size != ScryptRecipient.SCRYPT_SALT_SIZE)
      throw ScryptIdentityException("invalid scrypt recipient block")

    val digitsRe = "^[1-9][0-9]*$".toRegex()
    if (!stanza.args[1].matches(digitsRe))
      throw ScryptIdentityException("scrypt work factor encoding invalid: ${stanza.args[1]}")
    val workFactor =
      stanza.args[1].toIntOrNull()
        ?: throw ScryptIdentityException("scrypt work factor too large: ${stanza.args[1]}")

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
    // SCrypt uses 128 * N * r bytes for its main working buffer. With r=8 and N=2^18,
    // the default ceiling is 256 MiB. Higher budgets require an explicit constructor argument.
    // Keep this aligned with ScryptRecipient.DEFAULT_WORK_FACTOR for normal round trips.
    const val DEFAULT_MAX_WORK_FACTOR = 18
  }
}
