/**
 * Copyright 2021 The kage Authors. All rights reserved. Use of this source code is governed by
 * either an Apache 2.0 or MIT license at your discretion, that can be found in the LICENSE-APACHE
 * or LICENSE-MIT files respectively.
 */
package kage.format

import kage.errors.InvalidAgeKeyException
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import org.junit.Test

class AgeKeyTest {

  @Test
  fun testAgeKeyFile() {
    val keyString =
      """
      # created: 2006-01-02T15:04:05Z07:00
      # public key: age1mrmfnwhtlprn4jquex0ukmwcm7y2nxlphuzgsgv8ew2k9mewy3rs8u7su5
      AGE-SECRET-KEY-1EKYFFCK627939WTZMTT4ZRS2PM3U2K7PZ3MVGEL2M76W3PYJMSHQMTT6SS
    """.trimIndent()

    val reader = keyString.reader().buffered()
    val key = AgeKey.parse(reader)

    assertEquals("2006-01-02T15:04:05Z07:00", key.created)
    assertEquals(
      "age1mrmfnwhtlprn4jquex0ukmwcm7y2nxlphuzgsgv8ew2k9mewy3rs8u7su5",
      key.publicKey.decodeToString()
    )
    assertEquals(
      "AGE-SECRET-KEY-1EKYFFCK627939WTZMTT4ZRS2PM3U2K7PZ3MVGEL2M76W3PYJMSHQMTT6SS",
      key.privateKey.decodeToString()
    )
  }

  @Test
  fun testAgeKeyWithOnlyPrivateKey() {
    val keyString =
      """
      AGE-SECRET-KEY-1EKYFFCK627939WTZMTT4ZRS2PM3U2K7PZ3MVGEL2M76W3PYJMSHQMTT6SS
    """.trimIndent()

    val reader = keyString.reader().buffered()
    val key = AgeKey.parse(reader)

    assertEquals(
      "AGE-SECRET-KEY-1EKYFFCK627939WTZMTT4ZRS2PM3U2K7PZ3MVGEL2M76W3PYJMSHQMTT6SS",
      key.privateKey.decodeToString()
    )
  }

  @Test
  fun testAgeKeyWithInvalidPublicKeyThrowsException() {
    val keyString =
      """
      # created: 2006-01-02T15:04:05Z07:00
      # public key: not a valid public key
      AGE-SECRET-KEY-1EKYFFCK627939WTZMTT4ZRS2PM3U2K7PZ3MVGEL2M76W3PYJMSHQMTT6SS
    """.trimIndent()

    val reader = keyString.reader().buffered()

    assertFailsWith<InvalidAgeKeyException> { AgeKey.parse(reader) }
  }

  @Test
  fun testExtraDataIsIgnored() {
    val keyString =
      """
      # created: 2006-01-02T15:04:05Z07:00
      # something funny
      # not really
      AGE-SECRET-KEY-1EKYFFCK627939WTZMTT4ZRS2PM3U2K7PZ3MVGEL2M76W3PYJMSHQMTT6SS
    """.trimIndent()

    val reader = keyString.reader().buffered()
    val key = AgeKey.parse(reader)

    assertEquals("2006-01-02T15:04:05Z07:00", key.created)
    assertEquals(
      "AGE-SECRET-KEY-1EKYFFCK627939WTZMTT4ZRS2PM3U2K7PZ3MVGEL2M76W3PYJMSHQMTT6SS",
      key.privateKey.decodeToString()
    )
  }

  @Test
  fun testAgeKeyWithInvalidPrivateKeyThrowsException() {
    val keyString =
      """
      # created: 2006-01-02T15:04:05Z07:00
      1EKYFFCK627939WTZMTT4ZRS2PM3U2K7PZ3MVGEL2M76W3PYJMSHQMTT6SS
    """.trimIndent()

    val reader = keyString.reader().buffered()

    assertFailsWith<InvalidAgeKeyException> { AgeKey.parse(reader) }
  }

  @Test
  fun testAgeKeyWithDifferentOrder() {
    val keyString =
      """
      AGE-SECRET-KEY-1EKYFFCK627939WTZMTT4ZRS2PM3U2K7PZ3MVGEL2M76W3PYJMSHQMTT6SS
      # public key: age1mrmfnwhtlprn4jquex0ukmwcm7y2nxlphuzgsgv8ew2k9mewy3rs8u7su5
      # created: 2006-01-02T15:04:05Z07:00
    """.trimIndent()

    val reader = keyString.reader().buffered()
    val key = AgeKey.parse(reader)

    assertEquals("2006-01-02T15:04:05Z07:00", key.created)
    assertEquals(
      "age1mrmfnwhtlprn4jquex0ukmwcm7y2nxlphuzgsgv8ew2k9mewy3rs8u7su5",
      key.publicKey.decodeToString()
    )
    assertEquals(
      "AGE-SECRET-KEY-1EKYFFCK627939WTZMTT4ZRS2PM3U2K7PZ3MVGEL2M76W3PYJMSHQMTT6SS",
      key.privateKey.decodeToString()
    )
  }
}
