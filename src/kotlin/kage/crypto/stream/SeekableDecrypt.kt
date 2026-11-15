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
 * Decrypts an age STREAM payload at arbitrary offsets with [readAt].
 *
 * Unlike [DecryptInputStream], this does not read earlier chunks first. Open it with
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

  /** Gives the size of the decrypted plaintext in bytes. */
  public val plaintextSize: Long = payloadSize - chunks * MAC_SIZE

  private class CachedChunk(val chunkIndex: Long, val plaintext: ByteArray)

  private val cache = AtomicReference<CachedChunk>()

  init {
    // Authenticates the final chunk up front, so a truncated payload fails immediately rather
    // than only once a read reaches the end.
    cache.set(decryptChunk(chunks - 1))
  }

  /**
   * Reads plaintext into [dst] starting at byte [offset].
   *
   * Reads across chunk boundaries as needed. Returns fewer than the size of [dst] only when the
   * read reaches the end; returns `0` for an empty destination or an offset at [plaintextSize].
   *
   * @param dst destination byte array
   * @param offset plaintext byte offset, from `0` through [plaintextSize]
   * @return number of plaintext bytes read
   * @throws StreamException if [offset] is outside the plaintext or a chunk cannot be read or
   *   authenticated
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
      val chunks = ceilingDivide(payloadSize, ENC_CHUNK_SIZE)
      if (chunks <= 0) throw StreamException("invalid encrypted payload size: $payloadSize")
      val plaintextSize = payloadSize - chunks * MAC_SIZE
      val expectedChunks = if (plaintextSize == 0L) 1 else ceilingDivide(plaintextSize, CHUNK_SIZE)
      if (expectedChunks != chunks)
        throw StreamException("invalid encrypted payload size: $payloadSize")
      return chunks
    }

    fun ceilingDivide(dividend: Long, divisor: Int): Long =
      dividend / divisor + if (dividend % divisor == 0L) 0 else 1
  }
}
