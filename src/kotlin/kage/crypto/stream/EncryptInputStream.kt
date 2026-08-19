/**
 * Copyright 2022 The kage Authors. All rights reserved. Use of this source code is governed by
 * either an Apache 2.0 or MIT license at your discretion, that can be found in the LICENSE-APACHE
 * or LICENSE-MIT files respectively.
 */
package kage.crypto.stream

import java.io.InputStream
import kage.crypto.stream.ChaCha20Poly1305.NONCE_LENGTH
import kage.crypto.stream.EncryptOutputStream.Companion.CHUNK_SIZE
import kage.crypto.stream.Stream.incNonce
import kage.crypto.stream.Stream.setLastChunkFlag

/**
 * Reads plaintext from the underlying stream and provides encrypted data when calling `read`.
 *
 * This class is **not** thread safe.
 */
internal class EncryptInputStream(private val key: ByteArray, private val src: InputStream) :
  InputStream() {
  private val nonce = ByteArray(NONCE_LENGTH)
  private val singleByte = ByteArray(1)

  // One byte past CHUNK_SIZE so a full read tells us whether more plaintext follows, without
  // which we can't know whether this chunk is the last one to encrypt.
  private val buf = ByteArray(CHUNK_SIZE + 1)
  private var bufSize = 0

  private val encrypted = ByteArray(ChaCha20Poly1305.getEncryptOutputSize(CHUNK_SIZE))
  private var encryptedSize = 0
  private var encryptedOffset = 0
  private var streamDone = false

  override fun read(): Int {
    val n = read(singleByte, 0, 1)
    return if (n == -1) -1 else (singleByte[0].toInt() and 0xff)
  }

  override fun read(b: ByteArray, off: Int, len: Int): Int {
    if (len == 0) return 0
    if (encryptedOffset == encryptedSize) {
      if (streamDone) return -1
      encryptChunk()
    }
    val n = minOf(len, encryptedSize - encryptedOffset)
    encrypted.copyInto(b, off, encryptedOffset, encryptedOffset + n)
    encryptedOffset += n
    return n
  }

  private fun encryptChunk() {
    fillBuffer()

    val last = bufSize <= CHUNK_SIZE
    val chunkSize = if (last) bufSize else CHUNK_SIZE
    if (last) {
      setLastChunkFlag(nonce)
      streamDone = true
    }

    encryptedSize = ChaCha20Poly1305.encrypt(key, nonce, buf, 0, chunkSize, encrypted)
    encryptedOffset = 0
    incNonce(nonce)

    if (!last) {
      // Carry the peeked byte into the next chunk.
      buf[0] = buf[CHUNK_SIZE]
      bufSize = 1
    }
  }

  private fun fillBuffer() {
    while (bufSize < buf.size) {
      val n = src.read(buf, bufSize, buf.size - bufSize)
      if (n == -1) return
      bufSize += n
    }
  }

  override fun close() {
    src.close()
  }
}
