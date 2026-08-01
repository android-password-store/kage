/**
 * Copyright 2022 The kage Authors. All rights reserved. Use of this source code is governed by
 * either an Apache 2.0 or MIT license at your discretion, that can be found in the LICENSE-APACHE
 * or LICENSE-MIT files respectively.
 */
package kage

import com.google.common.truth.Truth.assertThat
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.security.SecureRandom
import java.util.Base64
import kage.crypto.x25519.X25519
import kage.crypto.x25519.X25519Identity
import kage.crypto.x25519.X25519Recipient
import kage.errors.InvalidRecipientException
import kage.format.AgeHeader
import kage.format.AgeStanza
import kage.utils.readLine
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows

class ShortReadStreamTest {
  /**
   * Wraps an [InputStream] and never returns more than one byte per buffered [read] call, so
   * callers that assume a single call fills the requested buffer are exercised the same way a file,
   * SAF (`content://`), or buffered stream would break them.
   */
  private class ShortReadInputStream(private val delegate: InputStream) : InputStream() {
    override fun read(): Int = delegate.read()

    override fun read(b: ByteArray, off: Int, len: Int): Int {
      if (len == 0) return 0
      val next = delegate.read()
      if (next == -1) return -1
      b[off] = next.toByte()
      return 1
    }
  }

  private fun genX25519Identity(): Pair<X25519Recipient, X25519Identity> {
    val privateKey = ByteArray(X25519Recipient.KEY_LENGTH)
    SecureRandom().nextBytes(privateKey)
    val publicKey = X25519.scalarMultBase(privateKey)

    return Pair(X25519Recipient(publicKey), X25519Identity(privateKey, publicKey))
  }

  private fun shortReads(bytes: ByteArray) = ShortReadInputStream(ByteArrayInputStream(bytes))

  @Test
  fun parseRecipientsSurvivesShortReads() {
    val headerString =
      """
      |age-encryption.org/v1
      |-> X25519 SVrzdFfkPxf0LPHOUGB1gNb9E5Vr8EUDa9kxk04iQ0o
      |0OrTkKHpE7klNLd0k+9Uam5hkQkzMxaqKcIPRIO1sNE
      |-> X25519 8hWaIUmk67IuRZ41zMk2V9f/w3f5qUnXLL7MGPA+zE8
      |tXgpAxKgqyu1jl9I/ATwFgV42ZbNgeAlvCTJ0WgvfEo
      |--- gxhoSa5BciRDt8lOpYNcx4EYtKpS0CJ06F3ZwN82VaM
      |"""
        .trimMargin()

    val header = AgeHeader.parse(shortReads(headerString.toByteArray()).buffered())
    val actualMac = Base64.getDecoder().decode("gxhoSa5BciRDt8lOpYNcx4EYtKpS0CJ06F3ZwN82VaM")

    assertThat(header.recipients).hasSize(2)
    assertThat(header.mac).asList().containsExactlyElementsIn(actualMac.asList())
  }

  @Test
  fun parseBodyLinesSurvivesShortReads() {
    val stanza =
      """
      |-> ssh-rsa SkdmSg
      |SW+xNSybDWTCkWx20FnCcxlfGC889s2hRxT8+giPH2DQMMFV6DyZpveqXtNwI3ts
      |5rVkW/7hCBSqEPQwabC6O5ls75uNjeSURwHAaIwtQ6riL9arjVpHMl8O7GWSRnx3
      |NltQt08ZpBAUkBqq5JKAr20t46ZinEIsD1LsDa2EnJrn0t8Truo2beGwZGkwkE2Y
      |
      |--- gxhoSa5BciRDt8lOpYNcx4EYtKpS0CJ06F3ZwN82VaM
      |"""
        .trimMargin()

    val reader = shortReads(stanza.toByteArray()).buffered()

    reader.readLine()

    val body = AgeStanza.parseBodyLines(reader)

    assertThat(Base64.getEncoder().withoutPadding().encodeToString(body))
      .isEqualTo(
        "SW+xNSybDWTCkWx20FnCcxlfGC889s2hRxT8+giPH2DQMMFV6DyZpveqXtNwI3ts" +
          "5rVkW/7hCBSqEPQwabC6O5ls75uNjeSURwHAaIwtQ6riL9arjVpHMl8O7GWSRnx3" +
          "NltQt08ZpBAUkBqq5JKAr20t46ZinEIsD1LsDa2EnJrn0t8Truo2beGwZGkwkE2Y"
      )
    assertThat(reader.readLine()).isEqualTo("--- gxhoSa5BciRDt8lOpYNcx4EYtKpS0CJ06F3ZwN82VaM")
  }

  @Test
  fun parseBodyLinesDetectsFooterUnderShortReads() {
    val stanza =
      """
      |-> X25519 SVrzdFfkPxf0LPHOUGB1gNb9E5Vr8EUDa9kxk04iQ0o
      |SW+xNSybDWTCkWx20FnCcxlfGC889s2hRxT8+giPH2DQMMFV6DyZpveqXtNwI3ts
      |--- gxhoSa5BciRDt8lOpYNcx4EYtKpS0CJ06F3ZwN82VaM
      |"""
        .trimMargin()

    val reader = shortReads(stanza.toByteArray()).buffered()

    reader.readLine()

    val err = assertThrows<InvalidRecipientException> { AgeStanza.parseBodyLines(reader) }
    assertThat(err).hasMessageThat().contains("Encountered the footer")
  }

  @Test
  fun decryptStreamSurvivesShortReads() {
    val (recipient1, identity1) = genX25519Identity()
    val (recipient2, _) = genX25519Identity()

    val payload = "this is my file"
    val ciphertext = ByteArrayOutputStream()
    Age.encryptStream(
      listOf(recipient1, recipient2),
      ByteArrayInputStream(payload.toByteArray()),
      ciphertext,
    )

    val decrypted = ByteArrayOutputStream()
    Age.decryptStream(listOf(identity1), shortReads(ciphertext.toByteArray()), decrypted)

    assertThat(decrypted.toByteArray().decodeToString()).isEqualTo(payload)
  }

  @Test
  fun decryptArmoredStreamSurvivesShortReads() {
    val (recipient, identity) = genX25519Identity()

    val payload = "this is my armored file"
    val ciphertext = ByteArrayOutputStream()
    Age.encryptStream(
      listOf(recipient),
      ByteArrayInputStream(payload.toByteArray()),
      ciphertext,
      generateArmor = true,
    )

    val decrypted = ByteArrayOutputStream()
    Age.decryptStream(listOf(identity), shortReads(ciphertext.toByteArray()), decrypted)

    assertThat(decrypted.toByteArray().decodeToString()).isEqualTo(payload)
  }
}
