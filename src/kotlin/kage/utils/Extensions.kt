/**
 * Copyright 2021 The kage Authors. All rights reserved. Use of this source code is governed by
 * either an Apache 2.0 or MIT license at your discretion, that can be found in the LICENSE-APACHE
 * or LICENSE-MIT files respectively.
 */
package kage.utils

import java.io.BufferedInputStream
import java.io.ByteArrayOutputStream
import java.io.Writer
import java.util.*

internal fun ByteArray.encodeBase64(): String {
  return Base64.getEncoder().withoutPadding().encodeToString(this)
}

internal fun String.decodeBase64(): ByteArray {
  return Base64.getDecoder().decode(this)
}

// Writer.newLine() uses System.lineSeparator(), we want to only use \n
internal fun Writer.writeNewLine() {
  write("\n")
}

internal fun Writer.writeSpace() {
  write(" ")
}

internal fun BufferedInputStream.readLine(): String? {
  val baos = ByteArrayOutputStream()

  while (true) {
    val r = this.read()

    if (r.toChar() == '\n') return baos.toByteArray().decodeToString()

    if (r != -1) baos.write(r)
    else if (baos.size() > 0) return baos.toByteArray().decodeToString() else return null
  }
}
