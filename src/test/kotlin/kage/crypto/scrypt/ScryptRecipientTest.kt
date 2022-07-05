/**
 * Copyright 2021 The kage Authors. All rights reserved. Use of this source code is governed by
 * either an Apache 2.0 or MIT license at your discretion, that can be found in the LICENSE-APACHE
 * or LICENSE-MIT files respectively.
 */
package kage.crypto.scrypt

import kage.utils.decodeBase64
import kotlin.test.assertEquals
import org.junit.Test

class ScryptRecipientTest {
  @Test
  fun testWrap() {
    val recipient = ScryptRecipient("mypass".toByteArray(), 18)

    val fileKey = ByteArray(32)

    val stanza = recipient.wrap(fileKey).first()

    val salt = stanza.args.first().decodeBase64()
    val workFactor = stanza.args[1].toInt()

    assertEquals(ScryptRecipient.SCRYPT_SALT_SIZE, salt.size)
    assertEquals(18, workFactor)
    assertEquals("scrypt", stanza.type)

    // TODO: Test this with `unwrap` when implemented
  }
}
