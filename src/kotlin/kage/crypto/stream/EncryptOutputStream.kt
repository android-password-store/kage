/**
 * Copyright 2022 The kage Authors. All rights reserved. Use of this source code is governed by
 * either an Apache 2.0 or MIT license at your discretion, that can be found in the LICENSE-APACHE
 * or LICENSE-MIT files respectively.
 */
package kage.crypto.stream

import java.io.OutputStream
import kage.crypto.stream.ChaCha20Poly1305.NONCE_LENGTH
import kage.crypto.stream.Stream.incNonce
import kage.crypto.stream.Stream.nonceIsZero
import kage.crypto.stream.Stream.setLastChunkFlag
import kage.errors.StreamException

/**
 * Encrypts data written to this OutputStream and writes the resulting ciphertext to the underlying
 * stream.
 *
 * This class is **not** thread safe.
 */
internal class EncryptOutputStream(private val key: ByteArray, private val dst: OutputStream) :
  OutputStream() {

  private val nonce = ByteArray(NONCE_LENGTH)

  private val buf = ByteArray(CHUNK_SIZE)
  private var bufSize = 0

  private val encryptOutputBuf = ByteArray(ChaCha20Poly1305.getEncryptOutputSize(buf.size))

  override fun write(i: Int) {
    write(byteArrayOf(i.toByte()))
  }

  override fun write(b: ByteArray, off: Int, len: Int) {
    var inputStart = off
    val inputEnd = off + len

    while (inputStart < inputEnd) {
      if (bufSize == CHUNK_SIZE) {
        flushChunk()
        bufSize = 0
      }

      val bufSpaceRemaining = CHUNK_SIZE - bufSize
      val copyLen = (inputEnd - inputStart).coerceAtMost(bufSpaceRemaining)

      b.copyInto(buf, bufSize, startIndex = inputStart, endIndex = inputStart + copyLen)
      bufSize += copyLen
      inputStart += copyLen
    }
  }

  override fun close() {
    flushChunk(last = true)
    dst.close()
  }

  private fun flushChunk(last: Boolean = false) {
    if (!last && bufSize != CHUNK_SIZE) {
      throw StreamException("internal error: flush called with partial chunk")
    }

    if (bufSize == 0 && !nonceIsZero(this.nonce))
      throw StreamException("only the first chunk can be empty")

    if (last) setLastChunkFlag(nonce)

    val encryptSize = ChaCha20Poly1305.encrypt(key, nonce, buf, 0, bufSize, encryptOutputBuf)

    dst.write(encryptOutputBuf, 0, encryptSize)

    incNonce(nonce)
  }

  internal companion object {
    const val CHUNK_SIZE = 64 * 1024
  }
}
