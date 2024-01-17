/**
 * Copyright 2022 The kage Authors. All rights reserved. Use of this source code is governed by
 * either an Apache 2.0 or MIT license at your discretion, that can be found in the LICENSE-APACHE
 * or LICENSE-MIT files respectively.
 */
package kage.format

import com.google.common.truth.Truth.assertThat
import java.io.ByteArrayOutputStream
import kage.crypto.x25519.X25519Identity
import kage.crypto.x25519.X25519Recipient
import kage.errors.InvalidAgeKeyException
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows

class AgeKeyFileTest {

  @Test
  fun testAgeKeyFile() {
    val keyString =
      """
      # created: 2006-01-02T15:04:05Z07:00
      # public key: age1mrmfnwhtlprn4jquex0ukmwcm7y2nxlphuzgsgv8ew2k9mewy3rs8u7su5
      AGE-SECRET-KEY-1EKYFFCK627939WTZMTT4ZRS2PM3U2K7PZ3MVGEL2M76W3PYJMSHQMTT6SS
    """
        .trimIndent()

    val reader = keyString.reader().buffered()
    val key = AgeKeyFile.parse(reader)

    assertThat(key.created).isEqualTo("2006-01-02T15:04:05Z07:00")
    assertThat(key.publicKey?.encodeToString())
      .isEqualTo("age1mrmfnwhtlprn4jquex0ukmwcm7y2nxlphuzgsgv8ew2k9mewy3rs8u7su5")
    assertThat(key.privateKey.encodeToString())
      .isEqualTo("AGE-SECRET-KEY-1EKYFFCK627939WTZMTT4ZRS2PM3U2K7PZ3MVGEL2M76W3PYJMSHQMTT6SS")
  }

  @Test
  fun testAgeKeyWithOnlyPrivateKey() {
    val keyString =
      """
      AGE-SECRET-KEY-1EKYFFCK627939WTZMTT4ZRS2PM3U2K7PZ3MVGEL2M76W3PYJMSHQMTT6SS
    """
        .trimIndent()

    val reader = keyString.reader().buffered()
    val key = AgeKeyFile.parse(reader)

    assertThat(key.privateKey.encodeToString())
      .isEqualTo("AGE-SECRET-KEY-1EKYFFCK627939WTZMTT4ZRS2PM3U2K7PZ3MVGEL2M76W3PYJMSHQMTT6SS")
  }

  @Test
  fun testAgeKeyWithInvalidPublicKeyThrowsException() {
    val keyString =
      """
      # created: 2006-01-02T15:04:05Z07:00
      # public key: not a valid public key
      AGE-SECRET-KEY-1EKYFFCK627939WTZMTT4ZRS2PM3U2K7PZ3MVGEL2M76W3PYJMSHQMTT6SS
    """
        .trimIndent()

    val reader = keyString.reader().buffered()

    assertThrows<InvalidAgeKeyException> { AgeKeyFile.parse(reader) }
  }

  @Test
  fun testExtraDataIsIgnored() {
    val keyString =
      """
      # created: 2006-01-02T15:04:05Z07:00
      # something funny
      # not really
      AGE-SECRET-KEY-1EKYFFCK627939WTZMTT4ZRS2PM3U2K7PZ3MVGEL2M76W3PYJMSHQMTT6SS
    """
        .trimIndent()

    val reader = keyString.reader().buffered()
    val key = AgeKeyFile.parse(reader)

    assertThat(key.created).isEqualTo("2006-01-02T15:04:05Z07:00")
    assertThat(key.privateKey.encodeToString())
      .isEqualTo("AGE-SECRET-KEY-1EKYFFCK627939WTZMTT4ZRS2PM3U2K7PZ3MVGEL2M76W3PYJMSHQMTT6SS")
  }

  @Test
  fun testAgeKeyWithInvalidPrivateKeyThrowsException() {
    val keyString =
      """
      # created: 2006-01-02T15:04:05Z07:00
      1EKYFFCK627939WTZMTT4ZRS2PM3U2K7PZ3MVGEL2M76W3PYJMSHQMTT6SS
    """
        .trimIndent()

    val reader = keyString.reader().buffered()

    assertThrows<InvalidAgeKeyException> { AgeKeyFile.parse(reader) }
  }

  @Test
  fun testAgeKeyWithDifferentOrder() {
    val keyString =
      """
      AGE-SECRET-KEY-1EKYFFCK627939WTZMTT4ZRS2PM3U2K7PZ3MVGEL2M76W3PYJMSHQMTT6SS
      # public key: age1mrmfnwhtlprn4jquex0ukmwcm7y2nxlphuzgsgv8ew2k9mewy3rs8u7su5
      # created: 2006-01-02T15:04:05Z07:00
    """
        .trimIndent()

    val reader = keyString.reader().buffered()
    val key = AgeKeyFile.parse(reader)

    assertThat(key.created).isEqualTo("2006-01-02T15:04:05Z07:00")
    assertThat(key.publicKey?.encodeToString())
      .isEqualTo("age1mrmfnwhtlprn4jquex0ukmwcm7y2nxlphuzgsgv8ew2k9mewy3rs8u7su5")
    assertThat(key.privateKey.encodeToString())
      .isEqualTo("AGE-SECRET-KEY-1EKYFFCK627939WTZMTT4ZRS2PM3U2K7PZ3MVGEL2M76W3PYJMSHQMTT6SS")
  }

  @Test
  fun testWrite() {
    val keyString =
      """
        # created: 2006-01-02T15:04:05Z07:00
        # public key: age1mrmfnwhtlprn4jquex0ukmwcm7y2nxlphuzgsgv8ew2k9mewy3rs8u7su5
        AGE-SECRET-KEY-1EKYFFCK627939WTZMTT4ZRS2PM3U2K7PZ3MVGEL2M76W3PYJMSHQMTT6SS
        
        """
        .trimIndent()

    val publicKey =
      X25519Recipient.decode("age1mrmfnwhtlprn4jquex0ukmwcm7y2nxlphuzgsgv8ew2k9mewy3rs8u7su5")

    val privateKey =
      X25519Identity.decode(
        "AGE-SECRET-KEY-1EKYFFCK627939WTZMTT4ZRS2PM3U2K7PZ3MVGEL2M76W3PYJMSHQMTT6SS"
      )

    val ageKeyFile = AgeKeyFile("2006-01-02T15:04:05Z07:00", publicKey, privateKey)

    val out = ByteArrayOutputStream()
    val writer = out.bufferedWriter()
    AgeKeyFile.write(writer, ageKeyFile)
    writer.flush()

    assertThat(out.toString()).isEqualTo(keyString)
  }
}
