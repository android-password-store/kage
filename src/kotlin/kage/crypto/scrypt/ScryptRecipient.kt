/**
 * Copyright 2021 The kage Authors. All rights reserved. Use of this source code is governed by
 * either an Apache 2.0 or MIT license at your discretion, that can be found in the LICENSE-APACHE
 * or LICENSE-MIT files respectively.
 */
package kage.crypto.scrypt

import java.security.SecureRandom
import kage.Recipient
import kage.crypto.chacha20.ChaCha20Poly1305
import kage.crypto.chacha20.ChaCha20Poly1305.CHACHA_20_POLY_1305_KEY_LENGTH
import kage.crypto.chacha20.ChaCha20Poly1305.CHACHA_20_POLY_1305_NONCE_LENGTH
import kage.format.AgeStanza
import kage.utils.encodeBase64
import org.bouncycastle.crypto.generators.SCrypt

public class ScryptRecipient(
  private val password: ByteArray,
  private val workFactor: Int = DEFAULT_WORK_FACTOR
) : Recipient {

  override fun wrap(fileKey: ByteArray): List<AgeStanza> {
    val salt = ByteArray(SCRYPT_SALT_SIZE)
    SecureRandom().nextBytes(salt)

    val logN = this.workFactor

    val fullSalt = SCRYPT_SALT_HEADER.toByteArray().plus(salt)

    val scryptKey =
      SCrypt.generate(password, fullSalt, 1 shl logN, 8, 1, CHACHA_20_POLY_1305_KEY_LENGTH)

    // From the spec: https://github.com/C2SP/C2SP/blob/main/age.md
    // "ChaCha20-Poly1305 nonce is fixed as 12 0x00 bytes [...]"
    val nonce = ByteArray(CHACHA_20_POLY_1305_NONCE_LENGTH)

    val wrappedKey = ChaCha20Poly1305.encrypt(scryptKey, nonce, fileKey)

    val stanza =
      AgeStanza(SCRYPT_STANZA_TYPE, listOf(salt.encodeBase64(), logN.toString()), wrappedKey)

    return listOf(stanza)
  }

  internal companion object {
    const val SCRYPT_SALT_SIZE = 16
    private const val SCRYPT_SALT_HEADER = "age-encryption.org/v1/scrypt"
    private const val DEFAULT_WORK_FACTOR = 18
    private const val SCRYPT_STANZA_TYPE = "scrypt"
  }
}
