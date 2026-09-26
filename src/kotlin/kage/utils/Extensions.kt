/**
 * Copyright 2022 The kage Authors. All rights reserved. Use of this source code is governed by
 * either an Apache 2.0 or MIT license at your discretion, that can be found in the LICENSE-APACHE
 * or LICENSE-MIT files respectively.
 */
package kage.utils

import java.io.BufferedInputStream
import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.io.Writer
import java.util.Base64
import kage.errors.InvalidBase64StringException

internal fun ByteArray.encodeBase64(isArmor: Boolean = false): String {
  return Base64.getEncoder().run { if (isArmor) this else withoutPadding() }.encodeToString(this)
}

internal fun String.decodeBase64(isArmor: Boolean = false): ByteArray {
  val (isCanonical, decoded) = this.isCanonicalBase64(isArmor)
  if (!isCanonical) throw InvalidBase64StringException()
  return decoded
}

internal fun String.isCanonicalBase64(isArmor: Boolean = false): Pair<Boolean, ByteArray> {
  val decodedByteArray = Base64.getDecoder().decode(this)
  // Armor can contain padding
  val encodedString =
    Base64.getEncoder()
      .run { if (isArmor) this else withoutPadding() }
      .encodeToString(decodedByteArray)
  return Pair(this == encodedString, decodedByteArray)
}

// Writer.newLine() uses System.lineSeparator(), we want to only use \n
internal fun Writer.writeNewLine() {
  write("\n")
}

internal fun Writer.writeSpace() {
  write(" ")
}

/**
 * Reads into [dst] until it is full or the stream is exhausted, returning the number of bytes read
 * (0 only at immediate EOF). A single [InputStream.read] may return fewer bytes than requested.
 */
internal fun InputStream.readFully(dst: ByteArray): Int {
  var offset = 0
  while (offset < dst.size) {
    val n = this.read(dst, offset, dst.size - offset)
    if (n == -1) break
    offset += n
  }
  return offset
}

internal class LineTooLongException : Exception()

internal class HeaderByteBudget(private val maxBytes: Int) {
  private var consumed = 0

  fun consumeByte() {
    if (consumed == maxBytes) throw HeaderTooLargeException()
    consumed++
  }
}

internal class HeaderTooLargeException : Exception()

internal fun BufferedInputStream.readLine(
  maxBytes: Int = Int.MAX_VALUE,
  budget: HeaderByteBudget? = null,
): String? {
  val baos = ByteArrayOutputStream(minOf(maxBytes, 256))

  while (true) {
    val r = this.read()
    if (r != -1) budget?.consumeByte()

    if (r == '\n'.code) {
      if (baos.size() >= maxBytes) throw LineTooLongException()
      return baos.toByteArray().decodeToString()
    }

    if (r != -1) {
      if (baos.size() == maxBytes) throw LineTooLongException()
      baos.write(r)
    } else if (baos.size() > 0) return baos.toByteArray().decodeToString() else return null
  }
}
