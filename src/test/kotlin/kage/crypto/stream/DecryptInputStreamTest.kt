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
