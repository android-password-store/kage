/**
 * Copyright 2022 The kage Authors. All rights reserved. Use of this source code is governed by
 * either an Apache 2.0 or MIT license at your discretion, that can be found in the LICENSE-APACHE
 * or LICENSE-MIT files respectively.
 */
package kage.crypto.stream

import java.util.concurrent.atomic.AtomicReference
import kage.crypto.stream.ChaCha20Poly1305.MAC_SIZE
import kage.crypto.stream.ChaCha20Poly1305.NONCE_LENGTH
import kage.crypto.stream.EncryptOutputStream.Companion.CHUNK_SIZE
import kage.crypto.stream.Stream.setLastChunkFlag
import kage.errors.StreamException

/**
 * Random access into an age STREAM payload: [readAt] can decrypt any offset directly, without
 * reading everything before it first, unlike [DecryptInputStream]. Construct with
 * [kage.Age.decryptSeekable].
 *
 * The most recently decrypted chunk is cached, and `readAt` is safe to call concurrently.
 */
public class SeekableDecrypt
internal constructor(
  private val key: ByteArray,
  private val source: RandomAccessSource,
  private val payloadOffset: Long,
  private val payloadSize: Long,
) {
  private val chunks: Long = encryptedChunkCount(payloadSize)

  /** Size of the decrypted plaintext, in bytes. */
  public val plaintextSize: Long = payloadSize - chunks * MAC_SIZE

  private class CachedChunk(val chunkIndex: Long, val plaintext: ByteArray)

  private val cache = AtomicReference<CachedChunk>()

  init {
    // Authenticates the final chunk up front, so a truncated payload fails immediately rather
    // than only once a read reaches the end.
    cache.set(decryptChunk(chunks - 1))
  }

  /**
   * Reads plaintext starting at [offset] into [dst]. Returns the number of bytes actually read,
   * which is less than `dst.size` only at the end of the plaintext.
   */
  public fun readAt(dst: ByteArray, offset: Long): Int {
    if (offset < 0 || offset > plaintextSize)
      throw StreamException("offset out of range [0:$plaintextSize]: $offset")
    if (dst.isEmpty() || offset == plaintextSize) return 0

    var written = 0
    var pos = offset
    while (written < dst.size && pos < plaintextSize) {
      val chunkIndex = pos / CHUNK_SIZE
      val cached = cache.get()
      val plaintext =
        if (cached != null && cached.chunkIndex == chunkIndex) {
          cached.plaintext
        } else {
          decryptChunk(chunkIndex).also { cache.set(it) }.plaintext
        }

      val chunkOffset = (pos - chunkIndex * CHUNK_SIZE).toInt()
      val copyLen = minOf(plaintext.size - chunkOffset, dst.size - written)
      plaintext.copyInto(dst, written, chunkOffset, chunkOffset + copyLen)
      written += copyLen
      pos += copyLen
    }
    return written
  }

  private fun decryptChunk(chunkIndex: Long): CachedChunk {
    val chunkOffset = chunkIndex * ENC_CHUNK_SIZE
    val chunkSize = minOf(payloadSize - chunkOffset, ENC_CHUNK_SIZE.toLong()).toInt()
    val encrypted = ByteArray(chunkSize)
    readFullyAt(encrypted, chunkOffset)

    val nonce = nonceForChunk(chunkIndex)
    if (chunkIndex == chunks - 1) setLastChunkFlag(nonce)

    val plaintext = ByteArray(chunkSize - MAC_SIZE)
    val decryptedSize =
      try {
        ChaCha20Poly1305.decrypt(key, nonce, encrypted, 0, chunkSize, plaintext, 0)
      } catch (e: Exception) {
        throw StreamException("failed to decrypt and authenticate chunk at offset $chunkOffset", e)
      }
    if (decryptedSize != plaintext.size)
      throw StreamException("short chunk decrypt at offset $chunkOffset: $decryptedSize")
    return CachedChunk(chunkIndex, plaintext)
  }

  private fun readFullyAt(dst: ByteArray, sourceOffset: Long) {
    var filled = 0
    while (filled < dst.size) {
      val n = source.readAt(dst, filled, dst.size - filled, payloadOffset + sourceOffset + filled)
      if (n <= 0)
        throw StreamException(
          "unexpected end of source while reading chunk at offset $sourceOffset"
        )
      filled += n
    }
  }

  private companion object {
    const val ENC_CHUNK_SIZE = CHUNK_SIZE + MAC_SIZE

    fun nonceForChunk(chunkIndex: Long): ByteArray {
      val nonce = ByteArray(NONCE_LENGTH)
      for (i in 0 until 8) {
        nonce[3 + i] = (chunkIndex ushr (8 * (7 - i)) and 0xFF).toByte()
      }
      return nonce
    }

    fun encryptedChunkCount(payloadSize: Long): Long {
      if (payloadSize < 0) throw StreamException("invalid encrypted payload size: $payloadSize")
      val chunks = (payloadSize + ENC_CHUNK_SIZE - 1) / ENC_CHUNK_SIZE
      val plaintextSize = payloadSize - chunks * MAC_SIZE
      var expectedChunks = (plaintextSize + CHUNK_SIZE - 1) / CHUNK_SIZE
      if (plaintextSize == 0L) expectedChunks = 1
      if (expectedChunks != chunks)
        throw StreamException("invalid encrypted payload size: $payloadSize")
      return chunks
    }
  }
}
