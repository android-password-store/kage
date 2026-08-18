/**
 * Copyright 2022 The kage Authors. All rights reserved. Use of this source code is governed by
 * either an Apache 2.0 or MIT license at your discretion, that can be found in the LICENSE-APACHE
 * or LICENSE-MIT files respectively.
 */
package kage.crypto.stream

import com.google.common.truth.Truth.assertThat
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.RandomAccessFile
import java.nio.file.Files
import kage.Age
import kage.crypto.x25519.X25519Identity
import kage.errors.StreamException
import kage.errors.X25519IdentityException
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows

class SeekableDecryptTest {
  private val identity = X25519Identity.`new`()

  // A full standalone age file, not Age.encrypt(...).body: that splits the header into a
  // separate field instead of prefixing it, so it isn't what decryptSeekable expects on disk.
  private fun encrypt(plaintext: ByteArray): ByteArray {
    val out = ByteArrayOutputStream()
    Age.encryptStream(listOf(identity.recipient()), ByteArrayInputStream(plaintext), out)
    return out.toByteArray()
  }

  private fun byteArraySource(data: ByteArray) =
    RandomAccessSource { dst, destOffset, length, sourceOffset ->
      if (sourceOffset >= data.size) {
        -1
      } else {
        val n = minOf(length.toLong(), data.size - sourceOffset).toInt()
        data.copyInto(dst, destOffset, sourceOffset.toInt(), sourceOffset.toInt() + n)
        n
      }
    }

  private fun readAll(decrypted: SeekableDecrypt): ByteArray {
    val out = ByteArray(decrypted.plaintextSize.toInt())
    val buf = ByteArray(1024)
    var offset = 0L
    while (offset < out.size) {
      val n = decrypted.readAt(buf, offset)
      if (n <= 0) break
      buf.copyInto(out, offset.toInt(), 0, n)
      offset += n
    }
    return out
  }

  // Chunk size is 64 KiB; these sizes exercise empty, sub-chunk, exactly-one-chunk, one-chunk-
  // plus-a-byte, and multi-chunk-with-a-partial-final-chunk payloads.
  private val sizes = listOf(0, 1, 100, 65536, 65537, 65536 * 3 + 42)

  @Test
  fun readAt_matchesTheOriginalPlaintextAtEveryChunkBoundary() {
    for (size in sizes) {
      val plaintext = ByteArray(size) { (it % 251).toByte() }
      val ciphertext = encrypt(plaintext)
      val decrypted =
        Age.decryptSeekable(listOf(identity), byteArraySource(ciphertext), ciphertext.size.toLong())

      assertThat(decrypted.plaintextSize).isEqualTo(size.toLong())
      assertThat(readAll(decrypted)).isEqualTo(plaintext)
    }
  }

  @Test
  fun readAt_returnsTheRightBytesForAnArbitraryMidFileOffset() {
    val plaintext = ByteArray(65536 * 3 + 42) { (it % 251).toByte() }
    val ciphertext = encrypt(plaintext)
    val decrypted =
      Age.decryptSeekable(listOf(identity), byteArraySource(ciphertext), ciphertext.size.toLong())

    // Straddles a chunk boundary: starts in chunk 0, the requested length runs into chunk 1.
    val offset = 65536L - 10
    val buf = ByteArray(20)
    val n = decrypted.readAt(buf, offset)

    assertThat(n).isEqualTo(20)
    assertThat(buf).isEqualTo(plaintext.copyOfRange(offset.toInt(), offset.toInt() + 20))
  }

  @Test
  fun readAt_worksAgainstARealFileChannel() {
    val plaintext = ByteArray(65536 + 500) { (it % 251).toByte() }
    val ciphertext = encrypt(plaintext)
    val file = Files.createTempFile("kage-seekable-decrypt-test", ".age")
    try {
      Files.write(file, ciphertext)
      RandomAccessFile(file.toFile(), "r").use { raf ->
        val source = RandomAccessSource.of(raf.channel)
        val decrypted = Age.decryptSeekable(listOf(identity), source, ciphertext.size.toLong())
        assertThat(readAll(decrypted)).isEqualTo(plaintext)
      }
    } finally {
      Files.deleteIfExists(file)
    }
  }

  @Test
  fun decryptSeekable_rejectsATruncatedFile() {
    val plaintext = ByteArray(65536 + 500) { (it % 251).toByte() }
    val ciphertext = encrypt(plaintext)
    val truncated = ciphertext.copyOfRange(0, ciphertext.size - 5)

    assertThrows<StreamException> {
      Age.decryptSeekable(listOf(identity), byteArraySource(truncated), truncated.size.toLong())
    }
  }

  @Test
  fun decryptSeekable_rejectsGarbageAppendedAfterTheLastChunk() {
    val plaintext = ByteArray(65536 + 500) { (it % 251).toByte() }
    val ciphertext = encrypt(plaintext) + byteArrayOf(1, 2, 3, 4)

    assertThrows<StreamException> {
      Age.decryptSeekable(listOf(identity), byteArraySource(ciphertext), ciphertext.size.toLong())
    }
  }

  @Test
  fun seekableDecrypt_rejectsANegativePayloadSize() {
    val key = ByteArray(ChaCha20Poly1305.KEY_LENGTH)

    assertThrows<StreamException> { SeekableDecrypt(key, byteArraySource(ByteArray(0)), 0L, -1L) }
  }

  @Test
  fun decryptSeekable_rejectsTheWrongIdentity() {
    val ciphertext = encrypt("hello".toByteArray())
    val wrongIdentity = X25519Identity.`new`()

    // X25519 stanzas carry no fingerprint hint (recipient-anonymous by design), so a wrong key
    // fails at AEAD authentication rather than a fast fingerprint mismatch.
    assertThrows<X25519IdentityException> {
      Age.decryptSeekable(
        listOf(wrongIdentity),
        byteArraySource(ciphertext),
        ciphertext.size.toLong(),
      )
    }
  }

  @Test
  fun readAt_rejectsAnOffsetPastTheEnd() {
    val ciphertext = encrypt("hello".toByteArray())
    val decrypted =
      Age.decryptSeekable(listOf(identity), byteArraySource(ciphertext), ciphertext.size.toLong())

    assertThrows<StreamException> { decrypted.readAt(ByteArray(1), decrypted.plaintextSize + 1) }
  }
}
