/**
 * Copyright 2025 The kage Authors. All rights reserved. Use of this source code is governed by
 * either an Apache 2.0 or MIT license at your discretion, that can be found in the LICENSE-APACHE
 * or LICENSE-MIT files respectively.
 */
package kage.kage.crypto.scrypt

import com.google.common.truth.Truth.assertThat
import kage.crypto.scrypt.ScryptIdentity
import kage.crypto.scrypt.ScryptRecipient
import kage.errors.ScryptIdentityException
import kage.format.AgeStanza
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertDoesNotThrow
import org.junit.jupiter.api.assertThrows

class ScryptIdentityTest {

  @Test
  fun unwrapWithBadBase64() {
    val stanza =
      AgeStanza(
        ScryptRecipient.SCRYPT_STANZA_TYPE,
        args = listOf("ABCDEF12357899999", "ZZZZ"),
        ByteArray(16),
      )

    val identity = ScryptIdentity("mypass".toByteArray())

    val exception = assertThrows<ScryptIdentityException> { identity.unwrap(listOf(stanza)) }
    assertThat(exception.message).contains("failed to parse scrypt salt")
  }

  @Test
  fun validateWorkFactor() {
    assertThrows<IllegalArgumentException> { ScryptIdentity("mypass".toByteArray(), 1) }
    assertThrows<IllegalArgumentException> { ScryptIdentity("mypass".toByteArray(), 31) }
    assertDoesNotThrow { ScryptIdentity("mypass".toByteArray(), 2) }
    assertDoesNotThrow { ScryptIdentity("mypass".toByteArray(), 30) }
  }
}
