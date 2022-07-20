/**
 * Copyright 2021 The kage Authors. All rights reserved. Use of this source code is governed by
 * either an Apache 2.0 or MIT license at your discretion, that can be found in the LICENSE-APACHE
 * or LICENSE-MIT files respectively.
 */
package kage.crypto.x25519

import at.favre.lib.crypto.HKDF
import com.github.michaelbull.result.getOrThrow
import com.github.michaelbull.result.mapError
import java.security.SecureRandom
import kage.Recipient
import kage.crypto.stream.ChaCha20Poly1305
import kage.errors.InvalidRecipientException
import kage.format.AgeKeyFile.Companion.AGE_PUBLIC_KEY_PREFIX
import kage.format.AgeStanza
import kage.format.Bech32
import kage.utils.encodeBase64

public class X25519Recipient(private val publicKey: ByteArray) : Recipient {

  override fun wrap(fileKey: ByteArray): List<AgeStanza> {
    val ephemeralSecret = ByteArray(EPHEMERAL_SECRET_LEN)
    SecureRandom().nextBytes(ephemeralSecret)

    val ephemeralShare = X25519.scalarMultBase(ephemeralSecret)

    val salt = ephemeralShare.plus(publicKey)

    val sharedSecret = X25519.scalarMult(ephemeralSecret, publicKey)

    val hkdf = HKDF.fromHmacSha256()

    val wrapingKey =
      hkdf.extractAndExpand(salt, sharedSecret, X25519_INFO.toByteArray(), MAC_KEY_LENGTH)

    val wrappedKey = ChaCha20Poly1305.aeadEncrypt(wrapingKey, fileKey)

    val stanza = AgeStanza(X25519_STANZA_TYPE, listOf(ephemeralShare.encodeBase64()), wrappedKey)

    return listOf(stanza)
  }

  public fun encodeToString(): String = Bech32.encode(AGE_PUBLIC_KEY_PREFIX, publicKey).getOrThrow()

  internal companion object {
    const val X25519_STANZA_TYPE = "X25519"
    const val X25519_INFO = "age-encryption.org/v1/X25519"
    const val KEY_LENGTH = 32 // bytes
    const val MAC_KEY_LENGTH = 32 // bytes
    const val EPHEMERAL_SECRET_LEN = 32 // bytes

    fun decode(string: String): X25519Recipient {
      val (hrp, key) =
        Bech32.decode(string)
          .mapError { InvalidRecipientException("Invalid public key", it) }
          .getOrThrow()

      if (key.size != KEY_LENGTH)
        throw InvalidRecipientException("Invalid key size for age public key (${key.size})")

      if (hrp != AGE_PUBLIC_KEY_PREFIX)
        throw InvalidRecipientException("Invalid human readable part for age public key ($hrp)")

      return X25519Recipient(key)
    }
  }
}
