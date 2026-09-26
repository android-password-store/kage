/**
 * Copyright 2023 The kage Authors. All rights reserved. Use of this source code is governed by
 * either an Apache 2.0 or MIT license at your discretion, that can be found in the LICENSE-APACHE
 * or LICENSE-MIT files respectively.
 */
package kage.crypto.stream

import com.google.common.truth.Truth.assertThat
import java.io.ByteArrayInputStream
import java.io.InputStream
import kage.errors.ArmorCodingException
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows

class ArmorInputStreamTest {
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

  private fun armor(trailing: String = "") =
    """-----BEGIN AGE ENCRYPTED FILE-----
AA==
-----END AGE ENCRYPTED FILE-----
$trailing"""

  @Test
  fun drainsTrailingWhitespaceThroughShortReads() {
    val stream =
      ArmorInputStream(ShortReadInputStream(ByteArrayInputStream(armor(" \t\n").toByteArray())))

    assertThat(stream.readAllBytes()).isEqualTo(byteArrayOf(0))
  }

  @Test
  fun rejectsCumulativeTrailingWhitespaceOverLimit() {
    val input = armor(" ".repeat(ArmorInputStream.MAX_WHITESPACE + 1)).toByteArray()
    val stream = ArmorInputStream(ShortReadInputStream(ByteArrayInputStream(input)))

    val error = assertThrows<ArmorCodingException> { stream.readAllBytes() }

    assertThat(error).hasMessageThat().isEqualTo("too much trailing whitespace")
  }

  @Test
  fun rejectsTrailingDataAfterMoreThanOneReadOfWhitespace() {
    val trailing = " ".repeat(ArmorInputStream.MAX_WHITESPACE - 1) + "x"
    val stream =
      ArmorInputStream(ShortReadInputStream(ByteArrayInputStream(armor(trailing).toByteArray())))

    val error = assertThrows<ArmorCodingException> { stream.readAllBytes() }

    assertThat(error).hasMessageThat().isEqualTo("trailing data after armored file")
  }
}
