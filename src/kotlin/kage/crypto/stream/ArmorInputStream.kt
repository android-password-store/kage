/**
 * Copyright 2023 The kage Authors. All rights reserved. Use of this source code is governed by
 * either an Apache 2.0 or MIT license at your discretion, that can be found in the LICENSE-APACHE
 * or LICENSE-MIT files respectively.
 */
package kage.crypto.stream

import java.io.InputStream
import java.lang.IllegalArgumentException
import kage.errors.ArmorCodingException
import kage.errors.InvalidBase64StringException
import kage.utils.decodeBase64

internal class ArmorInputStream(src: InputStream) : InputStream() {
  // Holds already decoded bytes
  private var unread = ByteArray(BYTES_PER_LINE)
  private var unreadSize = 0
  private var unreadOffset = 0

  private val srcReader = src.bufferedReader()

  private var started = false
  private var isEOF = false
  private var lastLineBytes = 0

  override fun read(): Int {
    if (!fillUnread()) return -1
    return unread[unreadOffset++].toInt() and 0xff
  }

  override fun read(dst: ByteArray, offset: Int, length: Int): Int {
    if (offset < 0 || length < 0 || length > dst.size - offset) {
      throw IndexOutOfBoundsException()
    }
    if (length == 0) return 0

    var copied = 0
    while (copied < length && fillUnread()) {
      val count = minOf(length - copied, unreadSize - unreadOffset)
      unread.copyInto(dst, offset + copied, unreadOffset, unreadOffset + count)
      unreadOffset += count
      copied += count
    }

    return if (copied == 0) -1 else copied
  }

  /** Makes decoded bytes available, reading and validating another armor line only when needed. */
  private fun fillUnread(): Boolean {
    if (unreadOffset < unreadSize) return true
    if (isEOF) return false

    if (!started) drainLeading()

    val line =
      readArmorLine(COLUMNS_PER_LINE)
        ?: throw ArmorCodingException("unexpected end of armored data")

    if (line == FOOTER) {
      drainTrailing()
      isEOF = true
      return false
    }

    if (line.isEmpty()) {
      throw ArmorCodingException("empty line in armored data")
    }

    unread =
      try {
        line.decodeBase64(isArmor = true)
      } catch (e: IllegalArgumentException) {
        val exc = ArmorCodingException("invalid base64 string")
        exc.addSuppressed(e)
        throw exc
      } catch (e: InvalidBase64StringException) {
        val exc = ArmorCodingException("missing base64 padding")
        exc.addSuppressed(e)
        throw exc
      }
    unreadSize = unread.size
    unreadOffset = 0

    if (unreadSize < BYTES_PER_LINE) {
      val trailingLine =
        try {
          readArmorLine(FOOTER.length)
        } catch (e: ArmorCodingException) {
          throw ArmorCodingException("invalid closing line")
        }

      if (trailingLine != FOOTER) throw ArmorCodingException("invalid closing line")

      drainTrailing()
      isEOF = true
    }

    return true
  }

  private fun drainLeading() {
    var removedWhitespace = 0

    while (!started) {
      val line =
        readArmorLine(MAX_WHITESPACE + 1) ?: throw ArmorCodingException("missing armor header")
      val trimmedLine = line.trim()

      if (trimmedLine.isEmpty()) {
        removedWhitespace += lastLineBytes

        if (removedWhitespace > MAX_WHITESPACE)
          throw ArmorCodingException("too much leading whitespace")

        continue
      }

      if (line != HEADER) throw ArmorCodingException("invalid first line: $line")

      started = true
    }
  }

  private fun readArmorLine(maxLength: Int): String? {
    val line = StringBuilder(minOf(maxLength, 64))
    lastLineBytes = 0
    while (true) {
      val c = srcReader.read()
      if (c == -1) {
        if (line.isEmpty()) return null
        if (line.length > maxLength) throw ArmorCodingException("column limit exceeded")
        return line.toString()
      }
      lastLineBytes++
      if (c == '\n'.code) {
        if (line.length > maxLength + 1 || (line.length == maxLength + 1 && line.last() != '\r'))
          throw ArmorCodingException("column limit exceeded")
        if (line.isNotEmpty() && line.last() == '\r') line.setLength(line.length - 1)
        return line.toString()
      }
      if (line.length == maxLength + 1 || (line.length == maxLength && c != '\r'.code))
        throw ArmorCodingException("column limit exceeded")
      line.append(c.toChar())
    }
  }

  private fun drainTrailing() {
    val buf = CharArray(256)
    var trailingWhitespace = 0

    while (true) {
      val bufSize = srcReader.read(buf)
      if (bufSize == -1) return

      for (index in 0 until bufSize) {
        if (!buf[index].isWhitespace()) {
          throw ArmorCodingException("trailing data after armored file")
        }

        trailingWhitespace++
        if (trailingWhitespace >= MAX_WHITESPACE) {
          throw ArmorCodingException("too much trailing whitespace")
        }
      }
    }
  }

  internal companion object {
    const val CRLF = "\\r\\n"
    const val HEADER_START = "-----"
    const val HEADER = "-----BEGIN AGE ENCRYPTED FILE-----"
    const val FOOTER = "-----END AGE ENCRYPTED FILE-----"

    const val COLUMNS_PER_LINE = 64
    const val BYTES_PER_LINE = COLUMNS_PER_LINE / 4 * 3
    const val MAX_WHITESPACE = 1024
  }
}
