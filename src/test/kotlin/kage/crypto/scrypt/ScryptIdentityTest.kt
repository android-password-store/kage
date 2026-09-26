/**
 * Copyright 2025 The kage Authors. All rights reserved. Use of this source code is governed by
 * either an Apache 2.0 or MIT license at your discretion, that can be found in the LICENSE-APACHE
 * or LICENSE-MIT files respectively.
 */
package kage.kage.crypto.scrypt

import com.google.common.truth.Truth.assertThat
import kage.Age
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
    // Larger limits remain available only through explicit configuration.
    assertDoesNotThrow { ScryptIdentity("mypass".toByteArray(), 30) }
  }

  @Test
  fun acceptsConfiguredBoundaryAndRejectsAboveItBeforeDerivation() {
    val password = "mypass".toByteArray()
    val fileKey = ByteArray(Age.FILE_KEY_SIZE)
    val stanzaAtLimit = ScryptRecipient(password, workFactor = 2).wrap(fileKey).single()

    assertThat(ScryptIdentity(password, maxWorkFactor = 2).unwrap(listOf(stanzaAtLimit)))
      .isEqualTo(fileKey)

    val overLimitArgs = stanzaAtLimit.args.toMutableList().apply { this[1] = "3" }
    val overLimitStanza = AgeStanza(stanzaAtLimit.type, overLimitArgs, stanzaAtLimit.body)
    val exception =
      assertThrows<ScryptIdentityException> {
        ScryptIdentity(password, maxWorkFactor = 2).unwrap(listOf(overLimitStanza))
      }
    assertThat(exception.message).contains("scrypt factor too large")
  }

  @Test
  fun defaultBudgetRejectsWorkFactorAbove256MiB() {
    val stanza =
      AgeStanza(
        ScryptRecipient.SCRYPT_STANZA_TYPE,
        args = listOf("AAAAAAAAAAAAAAAAAAAAAA", "19"),
        ByteArray(16),
      )

    val exception =
      assertThrows<ScryptIdentityException> {
        ScryptIdentity("mypass".toByteArray()).unwrap(listOf(stanza))
      }
    assertThat(exception.message).contains("scrypt factor too large: 19")
  }
}
