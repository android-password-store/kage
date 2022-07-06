/**
 * Copyright 2021 The kage Authors. All rights reserved. Use of this source code is governed by
 * either an Apache 2.0 or MIT license at your discretion, that can be found in the LICENSE-APACHE
 * or LICENSE-MIT files respectively.
 */
package kage.crypto.x25519

import at.favre.lib.crypto.HKDF
import java.security.SecureRandom
import kage.Recipient
import kage.crypto.chacha20.ChaCha20Poly1305
import kage.crypto.chacha20.ChaCha20Poly1305.CHACHA_20_POLY_1305_NONCE_LENGTH
import kage.format.AgeStanza
import kage.utils.encodeBase64

public class X25519Recipient(private val publicKey: ByteArray) : Recipient {

  override fun wrap(fileKey: ByteArray): List<AgeStanza> {
    val ephemeralSecret = ByteArray(EPHEMERAL_SECRET_LEN)
    SecureRandom().nextBytes(ephemeralSecret)

    val ephemeralShare = X25519.scalarMult(ephemeralSecret, X25519.BASEPOINT)

    val salt = ephemeralShare.plus(publicKey)

    val sharedSecret = X25519.scalarMult(ephemeralSecret, publicKey)

    val hkdf = HKDF.fromHmacSha256()

    val wrapingKey =
      hkdf.extractAndExpand(salt, sharedSecret, X25519_INFO.toByteArray(), MAC_KEY_LENGTH)

    val nonce = ByteArray(CHACHA_20_POLY_1305_NONCE_LENGTH)
    val wrappedKey = ChaCha20Poly1305.encrypt(wrapingKey, nonce, fileKey)

    val stanza = AgeStanza(X25519_STANZA_TYPE, listOf(ephemeralShare.encodeBase64()), wrappedKey)

    return listOf(stanza)
  }

  internal companion object {
    const val X25519_STANZA_TYPE = "X25519"
    const val X25519_INFO = "age-encryption.org/v1/X25519"
    const val MAC_KEY_LENGTH = 32 // bytes
    const val EPHEMERAL_SECRET_LEN = 32 // bytes
  }
}
