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
import org.junit.jupiter.api.assertThrows

class ScryptRecipientTest {
  @Test
  fun testRejectsOutOfRangeWorkFactor() {
    // Below the lower bound, plus values where `1 shl workFactor` overflows or wraps (31, 33).
    for (bad in listOf(Int.MIN_VALUE, -1, 0, 31, 32, 33, Int.MAX_VALUE)) {
      assertThrows<IllegalArgumentException>("workFactor=$bad should be rejected") {
        ScryptRecipient("mypass".toByteArray(), workFactor = bad)
      }
    }
    // The valid bounds construct without throwing.
    ScryptRecipient("mypass".toByteArray(), workFactor = 1)
    ScryptRecipient("mypass".toByteArray(), workFactor = 30)
  }

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
