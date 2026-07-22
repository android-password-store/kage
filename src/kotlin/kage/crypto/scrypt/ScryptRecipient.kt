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

/**
 * An age recipient that encrypts files with the supplied password.
 *
 * @param password Password bytes used to derive the wrapping key.
 * @param workFactor Base-2 logarithm of scrypt's CPU and memory cost parameter N.
 */
public class ScryptRecipient
@JvmOverloads
constructor(private val password: ByteArray, private val workFactor: Int = DEFAULT_WORK_FACTOR) :
  Recipient, RecipientWithLabels {

  init {
    // wrap() computes `1 shl workFactor`, whose shift is masked to 5 bits, so >= 31 silently wraps
    // to a weak N. Bound it to the range ScryptIdentity accepts on decrypt.
    require(workFactor in 1..30) { "workFactor must be in 1..30, was $workFactor" }
  }

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

  public companion object {
    /**
     * The default scrypt work factor: the base-2 logarithm of the CPU/memory cost parameter N, used
     * when a work factor is not supplied to the constructor. Exposed so callers can reference the
     * value kage applies by default, e.g. to surface it in a UI or to derive a relative one.
     */
    public const val DEFAULT_WORK_FACTOR: Int = 18

    internal const val SCRYPT_SALT_SIZE = 16
    internal const val SCRYPT_STANZA_TYPE = "scrypt"
    internal const val SCRYPT_SALT_LABEL = "age-encryption.org/v1/scrypt"
  }
}
