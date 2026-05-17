/**
 * Copyright 2023 The kage Authors. All rights reserved. Use of this source code is governed by
 * either an Apache 2.0 or MIT license at your discretion, that can be found in the LICENSE-APACHE
 * or LICENSE-MIT files respectively.
 */
package kage.crypto.stream

import java.io.OutputStream
import kage.utils.encodeBase64

internal class ArmorOutputStream(private val dst: OutputStream) : OutputStream() {

  private val buf = ByteArray(ArmorInputStream.BYTES_PER_LINE)
  private var bufSize = 0

  private var started = false

  override fun write(i: Int) {
    write(byteArrayOf(i.toByte()))
  }

  override fun write(b: ByteArray, off: Int, len: Int) {
    if (len == 0) {
      return
    }

    if (!started) {
      dst.write((ArmorInputStream.HEADER + "\n").toByteArray())
      started = true
    }

    var inputStart = off
    val inputEnd = off + len

    while (inputStart < inputEnd) {
      if (bufSize == ArmorInputStream.BYTES_PER_LINE) {
        writeLine()
        bufSize = 0
      }

      val bufSpaceRemaining = ArmorInputStream.BYTES_PER_LINE - bufSize
      val copyLen = (inputEnd - inputStart).coerceAtMost(bufSpaceRemaining)

      b.copyInto(buf, bufSize, startIndex = inputStart, endIndex = inputStart + copyLen)
      bufSize += copyLen
      inputStart += copyLen
    }
  }

  private fun writeLine() {
    if (bufSize > 0) {
      val b64Bytes = (buf.sliceArray(0 until bufSize)).encodeBase64(true).toByteArray()
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
