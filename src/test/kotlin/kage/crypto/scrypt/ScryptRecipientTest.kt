/**
 * Copyright 2022 The kage Authors. All rights reserved. Use of this source code is governed by
 * either an Apache 2.0 or MIT license at your discretion, that can be found in the LICENSE-APACHE
 * or LICENSE-MIT files respectively.
 */
package kage.crypto.scrypt

import com.google.common.truth.Truth.assertThat
import java.security.SecureRandom
import kage.Age
import org.junit.jupiter.api.Test

class ScryptRecipientTest {
  @Test
  fun testWrapUnwrap() {
    val recipient = ScryptRecipient("mypass".toByteArray(), workFactor = 1)

    val fileKey = ByteArray(Age.FILE_KEY_SIZE)
    SecureRandom().nextBytes(fileKey)

    val stanza = recipient.wrap(fileKey).first()

    val identity = ScryptIdentity("mypass".toByteArray())

    val unwrappedKey = identity.unwrap(listOf(stanza))

    assertThat(fileKey).asList().containsExactlyElementsIn(unwrappedKey.asList())
  }

  @Test
  fun testWrapUnwrapWithLabels() {
    val recipient = ScryptRecipient("mypass".toByteArray(), workFactor = 1)
    val fileKey = ByteArray(Age.FILE_KEY_SIZE)
    SecureRandom().nextBytes(fileKey)

    val (stanzas, labels) = recipient.wrapWithLabels(fileKey)

    val identity = ScryptIdentity("mypass".toByteArray())

    val unwrappedKey = identity.unwrap(listOf(stanzas.first()))

    assertThat(fileKey).asList().containsExactlyElementsIn(unwrappedKey.asList())
    assertThat(labels).isNotEmpty()
  }
}
