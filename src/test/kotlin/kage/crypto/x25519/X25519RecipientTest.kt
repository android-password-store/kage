/**
 * Copyright 2022 The kage Authors. All rights reserved. Use of this source code is governed by
 * either an Apache 2.0 or MIT license at your discretion, that can be found in the LICENSE-APACHE
 * or LICENSE-MIT files respectively.
 */
package kage.kage.crypto.x25519

import com.google.common.truth.Truth.assertThat
import java.security.SecureRandom
import java.util.Random
import kage.Age
import kage.crypto.x25519.X25519
import kage.crypto.x25519.X25519Identity
import kage.crypto.x25519.X25519Recipient
import kage.errors.X25519LowOrderPointException
import kage.utils.decodeBase64
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows

class X25519RecipientTest {
  @Test
  fun testWrapUnwrap() {
    val privateKey = ByteArray(32)
    SecureRandom().nextBytes(privateKey)
    val publicKey = X25519.scalarMultBase(privateKey)

    val recipient = X25519Recipient(publicKey)

    val fileKey = ByteArray(Age.FILE_KEY_SIZE)
    Random().nextBytes(fileKey)

    val stanza = recipient.wrap(fileKey).first()

    val sharedSecret = stanza.args.first().decodeBase64()

    assertThat(sharedSecret).hasLength(X25519Recipient.EPHEMERAL_SECRET_LEN)
    assertThat(stanza.type).isEqualTo(X25519Recipient.X25519_STANZA_TYPE)

    val identity = X25519Identity(privateKey, publicKey)

    val unwrapped = identity.unwrap(listOf(stanza))

    assertThat(fileKey).asList().containsExactlyElementsIn(unwrapped.asList())
  }

  @Test
  fun lowOrderX25519() {
    val privateKey = ByteArray(32)
    SecureRandom().nextBytes(privateKey)
    val sharedSecret = "X5yVvKNQjCSx0LFVnIPvWwREXMRYHI6G2CJO3dCfEdc".decodeBase64()
    assertThrows<X25519LowOrderPointException> { X25519.scalarMult(privateKey, sharedSecret) }
  }

  @Test
  fun identityX25519() {
    val privateKey = ByteArray(32)
    SecureRandom().nextBytes(privateKey)
    val sharedSecret = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".decodeBase64()
    assertThrows<X25519LowOrderPointException> { X25519.scalarMult(privateKey, sharedSecret) }
  }
}
