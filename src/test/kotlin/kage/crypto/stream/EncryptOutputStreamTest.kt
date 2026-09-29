/**
 * Copyright 2022 The kage Authors. All rights reserved. Use of this source code is governed by
 * either an Apache 2.0 or MIT license at your discretion, that can be found in the LICENSE-APACHE
 * or LICENSE-MIT files respectively.
 */
package kage.crypto.stream

import com.google.common.truth.Truth.assertThat
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.IOException
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows

class EncryptOutputStreamTest {
  private val key = ByteArray(32) { it.toByte() }

  @Test
  fun closeIsIdempotentForEmptyAndNonEmptyStreams() {
    for (plaintext in listOf(byteArrayOf(), "payload".toByteArray())) {
      val ciphertext = ByteArrayOutputStream()
      val stream = EncryptOutputStream(key, ciphertext)

      stream.write(plaintext)
      stream.close()
      val once = ciphertext.toByteArray()
      stream.close()

      assertThat(ciphertext.toByteArray()).isEqualTo(once)
      assertThat(DecryptInputStream(key, ByteArrayInputStream(once)).readAllBytes())
        .isEqualTo(plaintext)
      assertThrows<IOException> { stream.write(1) }
      assertThrows<IOException> { stream.write(byteArrayOf()) }
    }
  }

  @Test
  fun writeFlushesFullChunksBeforeTheFinalPartialChunk() {
    val plaintext = ByteArray(EncryptOutputStream.CHUNK_SIZE + 1) { (it % 251).toByte() }
    val ciphertext = ByteArrayOutputStream()
    val stream = EncryptOutputStream(key, ciphertext)

    stream.write(plaintext)
    stream.close()

    assertThat(
        DecryptInputStream(key, ByteArrayInputStream(ciphertext.toByteArray())).readAllBytes()
      )
      .isEqualTo(plaintext)
  }

  @Test
  fun armorCloseIsIdempotentForEmptyAndNonEmptyStreams() {
    for (payload in listOf(byteArrayOf(), "armored payload".toByteArray())) {
      val armored = ByteArrayOutputStream()
      val stream = ArmorOutputStream(armored)

      stream.write(payload)
      stream.close()
      val once = armored.toByteArray()
      stream.close()

      assertThat(armored.toByteArray()).isEqualTo(once)
      assertThrows<IOException> { stream.write(1) }
      assertThrows<IOException> { stream.write(byteArrayOf()) }

      if (payload.isEmpty()) {
        assertThat(once.decodeToString())
          .isEqualTo("${ArmorInputStream.HEADER}\n${ArmorInputStream.FOOTER}")
        assertThat(ArmorInputStream(ByteArrayInputStream(once)).readAllBytes()).isEmpty()
      } else {
        assertThat(ArmorInputStream(ByteArrayInputStream(once)).readAllBytes()).isEqualTo(payload)
      }
    }
  }

  @Test
  fun closingEncryptedStreamClosesWrappedArmorOnlyOnce() {
    val armored = ByteArrayOutputStream()
    val armor = ArmorOutputStream(armored)
    val encrypted = EncryptOutputStream(key, armor)
    val payload = "wrapped payload".toByteArray()

    encrypted.write(payload)
    encrypted.close()
    val once = armored.toByteArray()
    encrypted.close()
    armor.close()

    assertThat(armored.toByteArray()).isEqualTo(once)
    val ciphertext = ArmorInputStream(ByteArrayInputStream(once)).readAllBytes()
    assertThat(DecryptInputStream(key, ByteArrayInputStream(ciphertext)).readAllBytes())
      .isEqualTo(payload)
  }
}
