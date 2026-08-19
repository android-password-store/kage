/**
 * Copyright 2022 The kage Authors. All rights reserved. Use of this source code is governed by
 * either an Apache 2.0 or MIT license at your discretion, that can be found in the LICENSE-APACHE
 * or LICENSE-MIT files respectively.
 */
package kage.crypto.stream

import com.google.common.truth.Truth.assertThat
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.InputStream
import kage.Age
import kage.crypto.x25519.X25519Identity
import org.junit.jupiter.api.Test

class EncryptInputStreamTest {
  private val identity = X25519Identity.`new`()

  /**
   * Never returns more than one byte per [read] call, forcing [EncryptInputStream]'s buffer-fill
   * loop to run more than once per chunk instead of getting lucky with a single full read.
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

  private fun decrypt(ciphertext: ByteArray): ByteArray {
    val out = ByteArrayOutputStream()
    Age.decryptStream(listOf(identity), ByteArrayInputStream(ciphertext), out)
    return out.toByteArray()
  }

  // Chunk size is 64 KiB; these sizes exercise empty, sub-chunk, exactly-one-chunk, one-chunk-
  // plus-a-byte, and multi-chunk-with-a-partial-final-chunk payloads.
  private val sizes = listOf(0, 1, 100, 65536, 65537, 65536 * 3 + 42)

  @Test
  fun encryptReader_roundTripsAtEveryChunkBoundary() {
    for (size in sizes) {
      val plaintext = ByteArray(size) { (it % 251).toByte() }
      val ciphertext =
        Age.encryptReader(listOf(identity.recipient()), ByteArrayInputStream(plaintext))
          .readAllBytes()

      assertThat(decrypt(ciphertext)).isEqualTo(plaintext)
    }
  }

  @Test
  fun encryptReader_survivesShortReadsFromTheSource() {
    val plaintext = ByteArray(EncryptOutputStream.CHUNK_SIZE + 137) { (it % 251).toByte() }
    val src = ShortReadInputStream(ByteArrayInputStream(plaintext))

    val ciphertext = Age.encryptReader(listOf(identity.recipient()), src).readAllBytes()

    assertThat(decrypt(ciphertext)).isEqualTo(plaintext)
  }

  @Test
  fun encryptReader_closingTheStreamClosesTheSource() {
    var closed = false
    val src =
      object : InputStream() {
        override fun read() = -1

        override fun close() {
          closed = true
        }
      }

    Age.encryptReader(listOf(identity.recipient()), src).close()

    assertThat(closed).isTrue()
  }
}
