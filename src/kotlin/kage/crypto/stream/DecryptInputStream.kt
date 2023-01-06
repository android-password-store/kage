/**
 * Copyright 2022 The kage Authors. All rights reserved. Use of this source code is governed by
 * either an Apache 2.0 or MIT license at your discretion, that can be found in the LICENSE-APACHE
 * or LICENSE-MIT files respectively.
 */
package kage.crypto.stream

import java.io.EOFException
import java.io.InputStream
import kage.crypto.stream.ChaCha20Poly1305.NONCE_LENGTH
import kage.crypto.stream.EncryptOutputStream.Companion.CHUNK_SIZE
import kage.crypto.stream.Stream.incNonce
import kage.crypto.stream.Stream.nonceIsZero
import kage.crypto.stream.Stream.setLastChunkFlag
import kage.errors.StreamException

/**
 * Reads ciphertext from the underlying stream and provides decrypted data when calling `read`.
 *
 * This class is **not** thread safe.
 */
internal class DecryptInputStream(private val key: ByteArray, private val input: InputStream) :
  InputStream() {
  private val nonce = ByteArray(NONCE_LENGTH)

  // Holds encrypted text that was read from the underlying InputStream
  private val buf = ByteArray(CHUNK_SIZE + ChaCha20Poly1305.MAC_SIZE)
  private var bufSize = 0

  // Holds already decrypted plain text
  private val unread = ByteArray(CHUNK_SIZE)
  private var unreadSize = 0
  private var unreadOffset = 0

  private var inputEOF = false

  override fun read(): Int {
    if (unreadOffset < unreadSize) {
      return (unread[unreadOffset++].toInt() and 0xff)
    }

    if (inputEOF) // There is nothing else to read, and we read last chunk already
     return -1

    val last = readChunk()

    if (last) { // Check for more data after the last chunk
      inputEOF = true

      try {
        val next = input.read()

        if (next != -1) throw StreamException("trailing data after end of encrypted file")
      } catch (err: EOFException) {
        return -1
      }
    }

    // We tried to read more, but there wasn't anything, this stream is EOF
    if (unreadSize == 0) return -1

    return (unread[unreadOffset++].toInt() and 0xff)
  }

  // Returns true if this was the last chunk
  private fun readChunk(): Boolean {
    if (unreadOffset != unreadSize) throw StreamException("readChunk called with dirty buffer")

    var last = false

    val read = input.read(buf, 0, buf.size)
    bufSize = read

    if (read == -1) throw StreamException("Unexpected EOF. File ended without a marked chunk")

    if (read != buf.size) { // Incomplete chunk
      if (
        !nonceIsZero(nonce) && read == ChaCha20Poly1305.MAC_SIZE
      ) // Not the first chunk && the encrypted payload is empty
       throw StreamException("last chunk is empty")

      last = true
      setLastChunkFlag(this.nonce)
    }

    try {
      // Try to decode as a normal chunk, i.e. not the last
      unreadSize = ChaCha20Poly1305.decrypt(key, nonce, buf, 0, bufSize, unread, 0)
      unreadOffset = 0
    } catch (err: Exception) {
      if (last) // If we already tried to decode as last chunk, just throw the error
       throw StreamException("error occurred while decrypting stream", err)

      // Try to decode as a final chunk
      last = true
      setLastChunkFlag(this.nonce)

      try {
        unreadSize = ChaCha20Poly1305.decrypt(key, nonce, buf, 0, bufSize, unread, 0)
        unreadOffset = 0
      } catch (err: Exception) {
        throw StreamException("error occurred while decrypting stream", err)
      }

    }

    incNonce(this.nonce)

    return last
  }
}
