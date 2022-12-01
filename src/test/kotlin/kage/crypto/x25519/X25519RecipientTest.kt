/**
 * Copyright 2022 The kage Authors. All rights reserved. Use of this source code is governed by
 * either an Apache 2.0 or MIT license at your discretion, that can be found in the LICENSE-APACHE
 * or LICENSE-MIT files respectively.
 */
package kage.kage.crypto.x25519

import java.security.SecureRandom
import java.util.*
import kage.Age
import kage.crypto.x25519.X25519
import kage.crypto.x25519.X25519Identity
import kage.crypto.x25519.X25519Recipient
import kage.utils.decodeBase64
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import org.junit.Test

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

    assertEquals(X25519Recipient.EPHEMERAL_SECRET_LEN, sharedSecret.size)
    assertEquals(X25519Recipient.X25519_STANZA_TYPE, stanza.type)

    val identity = X25519Identity(privateKey, publicKey)

    val unwrapped = identity.unwrap(listOf(stanza))

    assertContentEquals(fileKey, unwrapped)
  }
}
