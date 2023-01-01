/**
 * Copyright 2023 The kage Authors. All rights reserved. Use of this source code is governed by
 * either an Apache 2.0 or MIT license at your discretion, that can be found in the LICENSE-APACHE
 * or LICENSE-MIT files respectively.
 */
package kage.crypto.stream

import java.io.OutputStream
import java.util.Base64

internal class ArmorOutputStream(private val dst: OutputStream) : OutputStream() {

  private val buf = ByteArray(ArmorInputStream.BYTES_PER_LINE)
  private var bufSize = 0

  private var started = false

  override fun write(i: Int) {
    if (!started) {
      dst.write((ArmorInputStream.HEADER + "\n").toByteArray())
      started = true
    }

    val b = i.toByte()

    if (bufSize == ArmorInputStream.BYTES_PER_LINE) {
      writeLine()
      bufSize = 0
    }

    buf[bufSize] = b
    bufSize++
  }

  private fun writeLine() {
    if (bufSize > 0) {
      val b64Bytes = Base64.getEncoder().withoutPadding().encode(buf.sliceArray(0 until bufSize))
      dst.write(b64Bytes)
    }

    dst.write('\n'.code)
  }

  override fun close() {
    writeLine()
    dst.write((ArmorInputStream.FOOTER).toByteArray())
    dst.close()
  }
}
