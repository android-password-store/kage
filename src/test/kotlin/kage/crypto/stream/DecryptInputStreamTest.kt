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
import java.security.SecureRandom
import kage.errors.StreamException
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Test

class DecryptInputStreamTest {
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

  @Test
  fun bulkAndSingleByteReadsCrossChunkBoundaries() {
    val key = ByteArray(ChaCha20Poly1305.KEY_LENGTH)
    SecureRandom().nextBytes(key)
    val payload = ByteArray(EncryptOutputStream.CHUNK_SIZE + 137)
    SecureRandom().nextBytes(payload)

    val ciphertext = ByteArrayOutputStream()
    EncryptInputStream(key, ByteArrayInputStream(payload)).use { it.copyTo(ciphertext) }
    val input = DecryptInputStream(key, ByteArrayInputStream(ciphertext.toByteArray()))
    val actual = ByteArrayOutputStream()
    val buffer = ByteArray(EncryptOutputStream.CHUNK_SIZE + 20)

    // Mix reads that stop within a chunk, land exactly on a boundary, and continue into the final
    // partial chunk. Offset reads also verify that bytes outside the requested range are untouched.
    val first = input.read(buffer, 3, EncryptOutputStream.CHUNK_SIZE - 4)
    assertThat(first).isEqualTo(EncryptOutputStream.CHUNK_SIZE - 4)
    actual.write(buffer, 3, first)
    assertThat(input.read()).isEqualTo(payload[EncryptOutputStream.CHUNK_SIZE - 4].toInt() and 0xff)
    actual.write(payload[EncryptOutputStream.CHUNK_SIZE - 4].toInt())

    buffer.fill(0x5a.toByte())
    val second = input.read(buffer, 5, buffer.size - 10)
    actual.write(buffer, 5, second)
    assertThat(buffer[4]).isEqualTo(0x5a.toByte())
    assertThat(buffer[buffer.size - 5]).isEqualTo(0x5a.toByte())

    assertThat(input.read(buffer, 0, buffer.size)).isEqualTo(-1)
    assertThat(input.read()).isEqualTo(-1)
    assertThat(actual.toByteArray().asList()).containsExactlyElementsIn(payload.asList())
  }

  @Test
  fun bulkReadHandlesEmptyAndPartialFinalChunks() {
    val key = ByteArray(ChaCha20Poly1305.KEY_LENGTH)
    SecureRandom().nextBytes(key)

    for (payload in listOf(ByteArray(0), ByteArray(73).also { SecureRandom().nextBytes(it) })) {
      val ciphertext = ByteArrayOutputStream()
      EncryptInputStream(key, ByteArrayInputStream(payload)).use { it.copyTo(ciphertext) }
      val input = DecryptInputStream(key, ByteArrayInputStream(ciphertext.toByteArray()))
      val buffer = ByteArray(100)

      assertThat(input.read(buffer, 10, 0)).isEqualTo(0)
      val count = input.read(buffer, 10, buffer.size - 10)
      assertThat(count).isEqualTo(if (payload.isEmpty()) -1 else payload.size)
      if (payload.isNotEmpty()) {
        assertThat(buffer.copyOfRange(10, 10 + count).asList())
          .containsExactlyElementsIn(payload.asList())
      }
      assertThat(input.read(buffer, 0, buffer.size)).isEqualTo(-1)
    }
  }

  @Test
  fun bulkReadRejectsInvalidRanges() {
    val input =
      DecryptInputStream(
        ByteArray(ChaCha20Poly1305.KEY_LENGTH),
        ByteArrayInputStream(byteArrayOf()),
      )
    val buffer = ByteArray(4)

    assertThrows(IndexOutOfBoundsException::class.java) { input.read(buffer, -1, 1) }
    assertThrows(IndexOutOfBoundsException::class.java) { input.read(buffer, 0, -1) }
    assertThrows(IndexOutOfBoundsException::class.java) { input.read(buffer, 3, 2) }
    assertThrows(IndexOutOfBoundsException::class.java) { input.read(buffer, 5, 0) }
  }

  @Test
  fun invalidFinalChunkAuthenticationFailsImmediately() {
    val key = ByteArray(ChaCha20Poly1305.KEY_LENGTH)
    val ciphertext = ByteArrayOutputStream()
    EncryptOutputStream(key, ciphertext).use { it.write("payload".toByteArray()) }
    val corrupted =
      ciphertext.toByteArray().also { it[it.lastIndex] = (it.last().toInt() xor 1).toByte() }

    assertThrows(StreamException::class.java) {
      DecryptInputStream(key, ByteArrayInputStream(corrupted)).readAllBytes()
    }
  }

  @Test
  fun readChunkSurvivesShortReads() {
    val key = ByteArray(ChaCha20Poly1305.KEY_LENGTH)
    SecureRandom().nextBytes(key)

    // Larger than a single chunk so readChunk's buffer fill runs more than once.
    val payload = ByteArray(EncryptOutputStream.CHUNK_SIZE + 137)
    SecureRandom().nextBytes(payload)

    val ciphertext = ByteArrayOutputStream()
    EncryptOutputStream(key, ciphertext).use { it.write(payload) }

    // InputStream.read(buf, off, len) is allowed to return fewer bytes than requested even
    // mid-stream (file, SAF and buffered streams all do this); ByteArrayInputStream always fills
    // the buffer in one call, which is why a short read being mistaken for the last chunk never
    // surfaced here. Force the worst case: never more than 1 byte per call.
    val input = ShortReadInputStream(ByteArrayInputStream(ciphertext.toByteArray()))
    val decrypted = DecryptInputStream(key, input).readAllBytes()

    assertThat(decrypted).asList().containsExactlyElementsIn(payload.asList())
  }
}
