/**
 * Copyright 2023 The kage Authors. All rights reserved. Use of this source code is governed by
 * either an Apache 2.0 or MIT license at your discretion, that can be found in the LICENSE-APACHE
 * or LICENSE-MIT files respectively.
 */
package kage.crypto.stream

import java.io.InputStream
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

  override fun read(): Int {
    if (unreadOffset < unreadSize) return (unread[unreadOffset++].toInt() and 0xff)

    if (isEOF) return -1

    if (!started) drainLeading()

    val line = srcReader.readLine()

    if (line == FOOTER) {
      drainTrailing()
      isEOF = true
      return -1
    }

    if (line.length > COLUMNS_PER_LINE) {
      throw ArmorCodingException("column limit exceeded")
    }

    unread =
      try {
        line.decodeBase64()
      } catch (e: InvalidBase64StringException) {
        val exc = ArmorCodingException("missing base64 padding")
        exc.addSuppressed(e)
        throw exc
      }
    unreadSize = unread.size
    unreadOffset = 0

    if (unreadSize < BYTES_PER_LINE) {
      val trailingLine = srcReader.readLine()

      if (trailingLine != FOOTER) throw ArmorCodingException("invalid closing line")

      drainTrailing()
      isEOF = true
    }

    return (unread[unreadOffset++].toInt() and 0xff)
  }

  private fun drainLeading() {
    var removedWhitespace = 0

    while (!started) {
      val line = srcReader.readLine()
      val trimmedLine = line.trim()

      if (trimmedLine.isEmpty()) {
        removedWhitespace += line.length + 1

        if (removedWhitespace > MAX_WHITESPACE)
          throw ArmorCodingException("too much leading whitespace")

        continue
      }

      if (line != HEADER) throw ArmorCodingException("invalid first line: $line")

      started = true
    }
  }

  private fun drainTrailing() {
    val buf = CharArray(MAX_WHITESPACE)
    val bufSize = srcReader.read(buf)

    val trailingText = if (bufSize > -1) buf.sliceArray(0 until bufSize).concatToString() else ""

    if (trailingText.trim().isNotEmpty())
      throw ArmorCodingException("trailing data after armored file")

    if (trailingText.length == MAX_WHITESPACE)
      throw ArmorCodingException("too much trailing whitespace")
  }

  internal companion object {
    const val HEADER = "-----BEGIN AGE ENCRYPTED FILE-----"
    const val FOOTER = "-----END AGE ENCRYPTED FILE-----"

    const val COLUMNS_PER_LINE = 64
    const val BYTES_PER_LINE = COLUMNS_PER_LINE / 4 * 3

    private const val MAX_WHITESPACE = 1024
  }
}
