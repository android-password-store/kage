/**
 * Copyright 2022 The kage Authors. All rights reserved. Use of this source code is governed by
 * either an Apache 2.0 or MIT license at your discretion, that can be found in the LICENSE-APACHE
 * or LICENSE-MIT files respectively.
 */
package kage.crypto.ssh

import java.security.MessageDigest

/**
 * OpenSSH's `bcrypt_pbkdf`: the KDF a passphrase-encrypted OpenSSH private key uses (`kdfname
 * "bcrypt"`) to turn a passphrase into the key/IV that unlock the private key section. Not standard
 * PBKDF2: a bcrypt-derived hash stands in for HMAC, and the output is interleaved rather than
 * written linearly.
 *
 * Ported from OpenBSD's `lib/libc/crypt/bcrypt_pbkdf.c` (ISC license: Ted Unangst, 2013), the
 * reference implementation OpenSSH itself vendors.
 */
internal object BcryptPbkdf {
  private const val HASH_SIZE = 32 // BCRYPT_WORDS(8) * 4
  private val MAGIC = "OxychromaticBlowfishSwatDynamite".toByteArray(Charsets.US_ASCII)

  /**
   * Derives [keyLength] bytes from [password] and [salt] over [rounds] stretching rounds. Throws
   * [IllegalArgumentException] on bad arguments, unlike the C version's "fill with random bytes and
   * return -1".
   */
  fun derive(password: ByteArray, salt: ByteArray, keyLength: Int, rounds: Int): ByteArray {
    require(rounds >= 1) { "rounds must be >= 1, was $rounds" }
    require(password.isNotEmpty()) { "password must not be empty" }
    require(salt.isNotEmpty()) { "salt must not be empty" }
    require(keyLength in 1..(HASH_SIZE * HASH_SIZE)) {
      "keyLength must be in 1..${HASH_SIZE * HASH_SIZE}, was $keyLength"
    }

    val key = ByteArray(keyLength)
    val sha2pass = sha512(password)

    // Output is produced HASH_SIZE bytes at a time and interleaved across `stride` positions
    // below, not written linearly.
    val stride = (keyLength + HASH_SIZE - 1) / HASH_SIZE
    var amt = (keyLength + stride - 1) / stride

    var count = 1
    var remaining = keyLength
    while (remaining > 0) {
      val countSalt =
        salt +
          byteArrayOf(
            (count ushr 24).toByte(),
            (count ushr 16).toByte(),
            (count ushr 8).toByte(),
            count.toByte(),
          )

      var tmpOut = bcryptHash(sha2pass, sha512(countSalt))
      val out = tmpOut.copyOf()
      for (i in 1 until rounds) {
        tmpOut = bcryptHash(sha2pass, sha512(tmpOut))
        for (j in out.indices) out[j] = (out[j].toInt() xor tmpOut[j].toInt()).toByte()
      }

      amt = minOf(amt, remaining)
      var written = 0
      while (written < amt) {
        val dest = written * stride + (count - 1)
        if (dest >= keyLength) break
        key[dest] = out[written]
        written++
      }
      remaining -= written
      count++
    }
    return key
  }

  /**
   * The bcrypt-derived hash `bcrypt_pbkdf` iterates: keys a fresh [Blowfish] schedule with 64
   * rounds of expensive expansion, then encrypts a fixed 32-byte constant 64 more times. Same cost
   * as bcrypt's own "OrpheanBeholderScryDoubt" step, with a different constant and output size.
   */
  private fun bcryptHash(sha2pass: ByteArray, sha2salt: ByteArray): ByteArray {
    val state = Blowfish()
    state.expandState(salt = sha2salt, key = sha2pass)
    repeat(64) {
      state.expand0State(sha2salt)
      state.expand0State(sha2pass)
    }

    // MAGIC is exactly 32 bytes (8 words), so this reads it once through, left to right, with no
    // wraparound.
    val cdata = IntArray(HASH_SIZE / 4)
    for (i in cdata.indices) {
      val o = i * 4
      cdata[i] =
        ((MAGIC[o].toInt() and 0xFF) shl 24) or
          ((MAGIC[o + 1].toInt() and 0xFF) shl 16) or
          ((MAGIC[o + 2].toInt() and 0xFF) shl 8) or
          (MAGIC[o + 3].toInt() and 0xFF)
    }
    val block = IntArray(2)
    repeat(64) {
      var i = 0
      while (i < cdata.size) {
        block[0] = cdata[i]
        block[1] = cdata[i + 1]
        state.encipher(block)
        cdata[i] = block[0]
        cdata[i + 1] = block[1]
        i += 2
      }
    }

    // Little-endian copy-out, unlike the big-endian reads elsewhere in bcrypt_pbkdf. Matches the
    // reference exactly, not a typo.
    val out = ByteArray(HASH_SIZE)
    for (i in cdata.indices) {
      out[4 * i] = cdata[i].toByte()
      out[4 * i + 1] = (cdata[i] ushr 8).toByte()
      out[4 * i + 2] = (cdata[i] ushr 16).toByte()
      out[4 * i + 3] = (cdata[i] ushr 24).toByte()
    }
    return out
  }

  private fun sha512(data: ByteArray): ByteArray = MessageDigest.getInstance("SHA-512").digest(data)
}
