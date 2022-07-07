/**
 * Copyright 2021 The kage Authors. All rights reserved. Use of this source code is governed by
 * either an Apache 2.0 or MIT license at your discretion, that can be found in the LICENSE-APACHE
 * or LICENSE-MIT files respectively.
 */
package kage.kage.crypto.x25519

import java.security.SecureRandom
import kage.crypto.x25519.X25519Recipient
import kage.utils.decodeBase64
import kotlin.test.assertEquals
import org.junit.Test

class X25519RecipientTest {
  @Test
  fun testWrap() {
    val publicKey = ByteArray(32)
    SecureRandom().nextBytes(publicKey)

    val recipient = X25519Recipient(publicKey)

    val fileKey = ByteArray(32)

    val stanza = recipient.wrap(fileKey).first()

    val sharedSecret = stanza.args.first().decodeBase64()

    assertEquals(X25519Recipient.EPHEMERAL_SECRET_LEN, sharedSecret.size)
    assertEquals(X25519Recipient.X25519_STANZA_TYPE, stanza.type)

    // TODO: Test this with `unwrap` when implemented
  }
}
