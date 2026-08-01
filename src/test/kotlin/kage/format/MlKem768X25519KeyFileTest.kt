/**
 * Copyright 2026 The kage Authors. All rights reserved. Use of this source code is governed by
 * either an Apache 2.0 or MIT license at your discretion, that can be found in the LICENSE-APACHE
 * or LICENSE-MIT files respectively.
 */
package kage.format

import com.google.common.truth.Truth.assertThat
import java.io.ByteArrayOutputStream
import kage.crypto.mlkem.MlKem768X25519Identity
import kage.crypto.mlkem.MlKem768X25519Recipient
import kage.errors.InvalidAgeKeyException
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows

class MlKem768X25519KeyFileTest {

  private val secretKey =
    "AGE-SECRET-KEY-PQ-1NQ3TF4DL0Z0K6E3RP2Q2TWGW87PZP5JGSU8EUAMMPU22W5WP688Q06M62A"

  private val publicKey = MlKem768X25519Identity.decode(secretKey).recipient().encodeToString()

  @Test
  fun testMlKem768X25519KeyFile() {
    val keyString =
      """
      # created: 2006-01-02T15:04:05Z07:00
      # public key: $publicKey
      $secretKey
      """
        .trimIndent()

    val reader = keyString.reader().buffered()
    val key = MlKem768X25519KeyFile.parse(reader)

    assertThat(key.created).isEqualTo("2006-01-02T15:04:05Z07:00")
    assertThat(key.publicKey?.encodeToString()).isEqualTo(publicKey)
    assertThat(key.privateKey.encodeToString()).isEqualTo(secretKey)
  }

  @Test
  fun testMlKem768X25519KeyWithOnlyPrivateKey() {
    val keyString = secretKey

    val reader = keyString.reader().buffered()
    val key = MlKem768X25519KeyFile.parse(reader)

    assertThat(key.privateKey.encodeToString()).isEqualTo(secretKey)
  }

  @Test
  fun testMlKem768X25519KeyWithInvalidPublicKeyThrowsException() {
    val keyString =
      """
      # created: 2006-01-02T15:04:05Z07:00
      # public key: not a valid public key
      $secretKey
      """
        .trimIndent()

    val reader = keyString.reader().buffered()

    assertThrows<InvalidAgeKeyException> { MlKem768X25519KeyFile.parse(reader) }
  }

  @Test
  fun testMlKem768X25519KeyWithX25519PublicKeyThrowsException() {
    val keyString =
      """
      # created: 2006-01-02T15:04:05Z07:00
      # public key: age1mrmfnwhtlprn4jquex0ukmwcm7y2nxlphuzgsgv8ew2k9mewy3rs8u7su5
      $secretKey
      """
        .trimIndent()

    val reader = keyString.reader().buffered()

    assertThrows<InvalidAgeKeyException> { MlKem768X25519KeyFile.parse(reader) }
  }

  @Test
  fun testExtraDataIsIgnored() {
    val keyString =
      """
      # created: 2006-01-02T15:04:05Z07:00
      # something funny
      # not really
      $secretKey
      """
        .trimIndent()

    val reader = keyString.reader().buffered()
    val key = MlKem768X25519KeyFile.parse(reader)

    assertThat(key.created).isEqualTo("2006-01-02T15:04:05Z07:00")
    assertThat(key.privateKey.encodeToString()).isEqualTo(secretKey)
  }

  @Test
  fun testMlKem768X25519KeyWithInvalidPrivateKeyThrowsException() {
    val keyString =
      """
      # created: 2006-01-02T15:04:05Z07:00
      1NQ3TF4DL0Z0K6E3RP2Q2TWGW87PZP5JGSU8EUAMMPU22W5WP688Q06M62A
      """
        .trimIndent()

    val reader = keyString.reader().buffered()

    assertThrows<InvalidAgeKeyException> { MlKem768X25519KeyFile.parse(reader) }
  }

  @Test
  fun testX25519PrivateKeyIsNotParsed() {
    val keyString =
      """
      # created: 2006-01-02T15:04:05Z07:00
      AGE-SECRET-KEY-1EKYFFCK627939WTZMTT4ZRS2PM3U2K7PZ3MVGEL2M76W3PYJMSHQMTT6SS
      """
        .trimIndent()

    val reader = keyString.reader().buffered()

    assertThrows<InvalidAgeKeyException> { MlKem768X25519KeyFile.parse(reader) }
  }

  @Test
  fun testMlKem768X25519KeyWithDifferentOrder() {
    val keyString =
      """
      $secretKey
      # public key: $publicKey
      # created: 2006-01-02T15:04:05Z07:00
      """
        .trimIndent()

    val reader = keyString.reader().buffered()
    val key = MlKem768X25519KeyFile.parse(reader)

    assertThat(key.created).isEqualTo("2006-01-02T15:04:05Z07:00")
    assertThat(key.publicKey?.encodeToString()).isEqualTo(publicKey)
    assertThat(key.privateKey.encodeToString()).isEqualTo(secretKey)
  }

  @Test
  fun testRejectsPublicKeyThatDoesNotMatchPrivateKey() {
    val otherPublicKey = MlKem768X25519Identity.new().recipient().encodeToString()
    val keyString =
      """
      # public key: $otherPublicKey
      $secretKey
      """
        .trimIndent()

    assertThrows<InvalidAgeKeyException> {
      MlKem768X25519KeyFile.parse(keyString.reader().buffered())
    }
  }

  @Test
  fun testPrivateOnlyKeyFilesWithSameIdentityAreEqual() {
    val identity = MlKem768X25519Identity.decode(secretKey)
    val first = MlKem768X25519KeyFile("", null, identity)
    val second = MlKem768X25519KeyFile("", null, identity)

    assertThat(first).isEqualTo(second)
    assertThat(first.hashCode()).isEqualTo(second.hashCode())
  }

  @Test
  fun testWrite() {
    val keyString =
      """
      # created: 2006-01-02T15:04:05Z07:00
      # public key: $publicKey
      $secretKey

      """
        .trimIndent()

    val keyFile =
      MlKem768X25519KeyFile(
        "2006-01-02T15:04:05Z07:00",
        MlKem768X25519Recipient.decode(publicKey),
        MlKem768X25519Identity.decode(secretKey),
      )

    val out = ByteArrayOutputStream()
    val writer = out.bufferedWriter()
    MlKem768X25519KeyFile.write(writer, keyFile)
    writer.flush()

    assertThat(out.toString()).isEqualTo(keyString)
  }

  @Test
  fun testWriteParseRoundTrip() {
    val identity = MlKem768X25519Identity.new()
    val keyFile = MlKem768X25519KeyFile("2006-01-02T15:04:05Z07:00", identity.recipient(), identity)

    val out = ByteArrayOutputStream()
    val writer = out.bufferedWriter()
    MlKem768X25519KeyFile.write(writer, keyFile)
    writer.flush()

    val parsed = MlKem768X25519KeyFile.parse(out.toString().reader().buffered())

    assertThat(parsed.created).isEqualTo("2006-01-02T15:04:05Z07:00")
    assertThat(parsed.publicKey?.encodeToString()).isEqualTo(identity.recipient().encodeToString())
    assertThat(parsed.privateKey.encodeToString()).isEqualTo(identity.encodeToString())
  }
}
