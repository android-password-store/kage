/**
 * Copyright 2022 The kage Authors. All rights reserved. Use of this source code is governed by
 * either an Apache 2.0 or MIT license at your discretion, that can be found in the LICENSE-APACHE
 * or LICENSE-MIT files respectively.
 */
package kage.crypto.scrypt

import java.security.SecureRandom
import kage.Recipient
import kage.RecipientWithLabels
import kage.crypto.stream.ChaCha20Poly1305
import kage.crypto.stream.ChaCha20Poly1305.KEY_LENGTH
import kage.format.AgeStanza
import kage.utils.encodeBase64
import org.bouncycastle.crypto.generators.SCrypt

public class ScryptRecipient
@JvmOverloads
constructor(private val password: ByteArray, private val workFactor: Int = DEFAULT_WORK_FACTOR) :
  Recipient, RecipientWithLabels {

  override fun wrap(fileKey: ByteArray): List<AgeStanza> {
    val salt = ByteArray(SCRYPT_SALT_SIZE)
    SecureRandom().nextBytes(salt)

    val logN = this.workFactor

    val fullSalt = SCRYPT_SALT_LABEL.toByteArray().plus(salt)

    val scryptKey = SCrypt.generate(password, fullSalt, 1 shl logN, 8, 1, KEY_LENGTH)

    val wrappedKey = ChaCha20Poly1305.aeadEncrypt(scryptKey, fileKey)

    val stanza =
      AgeStanza(SCRYPT_STANZA_TYPE, listOf(salt.encodeBase64(), logN.toString()), wrappedKey)

    return listOf(stanza)
  }

  override fun wrapWithLabels(fileKey: ByteArray): Pair<List<AgeStanza>, List<String>> {
    val stanzas = wrap(fileKey)
    val label = ByteArray(16)
    SecureRandom().nextBytes(label)

    return Pair(stanzas, listOf(label.encodeBase64()))
  }

  internal companion object {
    const val SCRYPT_SALT_SIZE = 16
    const val SCRYPT_STANZA_TYPE = "scrypt"
    const val SCRYPT_SALT_LABEL = "age-encryption.org/v1/scrypt"
    const val DEFAULT_WORK_FACTOR = 18
  }
}
