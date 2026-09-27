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
import kage.utils.encodeBase64
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

  @Test
  fun mixedReadsCrossDecodedLineBoundaries() {
    val payload = ByteArray(ArmorInputStream.BYTES_PER_LINE * 2 + 7) { it.toByte() }
    val armor = armor(payload)
    val input = ArmorInputStream(ByteArrayInputStream(armor.toByteArray()))

    val first = ByteArray(13)
    assertThat(input.read(first, 0, first.size)).isEqualTo(first.size)
    assertThat(first).asList().containsExactlyElementsIn(payload.sliceArray(0 until 13).asList())
    assertThat(input.read()).isEqualTo(payload[13].toInt() and 0xff)

    val rest = ByteArray(payload.size)
    val count = input.read(rest, 5, rest.size - 5)

    assertThat(count).isEqualTo(payload.size - 14)
    assertThat(rest.sliceArray(5 until 5 + count).asList())
      .containsExactlyElementsIn(payload.sliceArray(14 until payload.size).asList())
    assertThat(input.read()).isEqualTo(-1)
    assertThat(input.read(ByteArray(8), 0, 8)).isEqualTo(-1)
  }

  @Test
  fun bulkReadValidatesNextLineWhenCurrentDecodedBufferIsExhausted() {
    val payload = ByteArray(ArmorInputStream.BYTES_PER_LINE) { it.toByte() }
    val armor = buildString {
      appendLine(ArmorInputStream.HEADER)
      appendLine(payload.encodeBase64(isArmor = true))
      appendLine("not base64")
      appendLine(ArmorInputStream.FOOTER)
    }
    val input = ArmorInputStream(ByteArrayInputStream(armor.toByteArray()))

    val firstLine = ByteArray(payload.size)
    assertThat(input.read(firstLine, 0, firstLine.size)).isEqualTo(payload.size)
    assertThat(firstLine.asList()).containsExactlyElementsIn(payload.asList())
    assertThrows<ArmorCodingException> { input.read(ByteArray(1), 0, 1) }
  }

  private fun armor(payload: ByteArray): String = buildString {
    appendLine(ArmorInputStream.HEADER)
    payload.asList().chunked(ArmorInputStream.BYTES_PER_LINE).forEach { chunk ->
      appendLine(chunk.toByteArray().encodeBase64(isArmor = true))
    }
    appendLine(ArmorInputStream.FOOTER)
  }
}
