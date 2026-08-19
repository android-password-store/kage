/**
 * Copyright 2022 The kage Authors. All rights reserved. Use of this source code is governed by
 * either an Apache 2.0 or MIT license at your discretion, that can be found in the LICENSE-APACHE
 * or LICENSE-MIT files respectively.
 */
package kage

import com.google.common.truth.Truth.assertThat
import java.io.BufferedReader
import java.io.StringReader
import kage.crypto.mlkem.MlKem768X25519Identity
import kage.crypto.mlkem.MlKem768X25519Recipient
import kage.crypto.x25519.X25519Identity
import kage.crypto.x25519.X25519Recipient
import kage.errors.InvalidIdentityFileException
import kage.errors.InvalidRecipientFileException
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows

class AgeParseTest {
  private fun reader(text: String): BufferedReader = BufferedReader(StringReader(text))

  @Test
  fun parseIdentities_skipsCommentsAndBlankLines() {
    val file =
      """

      # this is a comment
      # AGE-SECRET-KEY-1705XN76M8EYQ8M9PY4E2G3KA8DN7NSCGT3V4HMN20H3GCX4AS6HSSTG8D3
      #

      AGE-SECRET-KEY-1D6K0SGAX3NU66R4GYFZY0UQWCLM3UUSF3CXLW4KXZM342WQSJ82QKU59QJ
      AGE-SECRET-KEY-19WUMFE89H3928FRJ5U3JYRNHM6CERQGKSQ584AQ8QY7T7R09D32SWE4DYH
      """
        .trimIndent()

    assertThat(Age.parseIdentities(reader(file))).hasSize(2)
  }

  @Test
  fun parseIdentities_rejectsAMalformedIdentity() {
    val file =
      """
      AGE-SECRET-KEY-1705XN76M8EYQ8M9PY4E2G3KA8DN7NSCGT3V4HMN20H3GCX4AS6HSSTG8D3
      AGE-SECRET-KEY--1D6K0SGAX3NU66R4GYFZY0UQWCLM3UUSF3CXLW4KXZM342WQSJ82QKU59Q
      """
        .trimIndent()

    assertThrows<InvalidIdentityFileException> { Age.parseIdentities(reader(file)) }
  }

  @Test
  fun parseIdentities_rejectsAnEmptyFile() {
    assertThrows<InvalidIdentityFileException> { Age.parseIdentities(reader("# only a comment")) }
  }

  @Test
  fun parseIdentities_recognizesHybridPqIdentities() {
    val x25519 = X25519Identity.new()
    val hybrid = MlKem768X25519Identity.new()
    val file = "${x25519.encodeToString()}\n${hybrid.encodeToString()}"

    val identities = Age.parseIdentities(reader(file))

    assertThat(identities).hasSize(2)
    assertThat(identities[0]).isInstanceOf(X25519Identity::class.java)
    assertThat(identities[1]).isInstanceOf(MlKem768X25519Identity::class.java)
  }

  @Test
  fun parseRecipients_recognizesX25519AndHybridPqRecipients() {
    val x25519 = X25519Identity.new().recipient()
    val hybrid = MlKem768X25519Identity.new().recipient()
    val file = "${x25519.encodeToString()}\n${hybrid.encodeToString()}"

    val recipients = Age.parseRecipients(reader(file))

    assertThat(recipients).hasSize(2)
    assertThat(recipients[0]).isInstanceOf(X25519Recipient::class.java)
    assertThat(recipients[1]).isInstanceOf(MlKem768X25519Recipient::class.java)
  }

  @Test
  fun parseRecipients_rejectsAnUnknownLine() {
    assertThrows<InvalidRecipientFileException> {
      Age.parseRecipients(reader("not-a-recipient"))
    }
  }

  @Test
  fun parseRecipients_rejectsAnEmptyFile() {
    assertThrows<InvalidRecipientFileException> { Age.parseRecipients(reader("")) }
  }
}
