/**
 * Copyright 2021 The kage Authors. All rights reserved. Use of this source code is governed by
 * either an Apache 2.0 or MIT license at your discretion, that can be found in the LICENSE-APACHE
 * or LICENSE-MIT files respectively.
 */
package kage.crypto.chacha20

import java.io.OutputStream
import kage.crypto.chacha20.ChaCha20Poly1305.CHACHA_20_POLY_1305_NONCE_LENGTH

// TODO: This is not thread safe
internal class ChaCha20Poly1305OutputStream(
  private val key: ByteArray,
  private val dst: OutputStream
) : OutputStream() {

  private val nonce = ByteArray(CHACHA_20_POLY_1305_NONCE_LENGTH)

  private val buf = ByteArray(CHUNK_SIZE)
  private var bufSize = 0

  override fun write(i: Int) {
    val b = i.toByte()

    buf[bufSize] = b
    bufSize++

    if (bufSize == CHUNK_SIZE) {
      flushChunk()
      bufSize = 0
    }
  }

  override fun close() {
    flushChunk(last = true)
    // Not closing underlying stream
  }

  /*
  This will encrypt an empty block when the last buffer is empty. That is, when the playload size is a multiple of
  `chunkSize`, the last encrypted block will contain an empty payload, encrypted using a nonce with the `last` flag set.
  to 1.

  The spec explicitly says this must not happen:

  > The final chunk MAY be shorter than 64 KiB but MUST NOT be empty unless the whole payload is empty.

  However, the go implementation does the same as this code and getting around this would be tricky as we'd have to go
  back after writing and encrypt the last chunk again with a different nonce, with the `last` flag set to 1.

  Maybe the spec means the last **encrypted** chunk must not be empty?
   */
  private fun flushChunk(last: Boolean = false) {
    if (!last && bufSize != CHUNK_SIZE) {
      throw RuntimeException("internal error: flush called with partial chunk")
    }

    if (last) {
      nonce[nonce.size - 1] = 0x01
    }

    val chunk = ChaCha20Poly1305.encrypt(key, nonce, buf, 0, bufSize)

    dst.write(chunk)

    incNonce()
  }

  private fun incNonce() {
    for (i in nonce.size - 2 downTo 0) {
      nonce[i]++

      if (nonce[i] != 0.toByte()) break
      else if (i == 0) throw RuntimeException("stream: chunk counter wrapped around")
    }
  }

  internal companion object {
    const val CHUNK_SIZE = 64 * 1024
  }
}
