/**
 * Copyright 2022 The kage Authors. All rights reserved. Use of this source code is governed by
 * either an Apache 2.0 or MIT license at your discretion, that can be found in the LICENSE-APACHE
 * or LICENSE-MIT files respectively.
 */
package kage.crypto.ssh

/**
 * Blowfish, restricted to the "expensive key schedule" primitives OpenSSH's `bcrypt_pbkdf` builds
 * on: [expand0State] and [expandState]. Not a general-purpose cipher, this exists purely to derive
 * the unlock key for a passphrase-encrypted OpenSSH private key (see [BcryptPbkdf]).
 *
 * Ported from OpenBSD's `lib/libc/crypt/blowfish.c` (ISC license: Niels Provos, 1997), the same
 * reference source OpenSSH itself vendors. P-box/S-box constants are the hexadecimal digits of pi,
 * as in every Blowfish implementation. The S-boxes are one flat 1024-entry array (`S[box*256 + i]`)
 * rather than `Array<IntArray>`, matching C's contiguous `S[4][256]` layout.
 */
internal class Blowfish {
  private val p: IntArray = INITIAL_P.copyOf()
  private val s: IntArray = INITIAL_S.copyOf()

  /**
   * Enciphers one 64-bit block in place: `block[0]` is the left half, `block[1]` the right half.
   */
  fun encipher(block: IntArray) {
    var xl = block[0] xor p[0]
    var xr = block[1]
    var i = 1
    while (i <= 15) {
      xr = xr xor (f(xl) xor p[i])
      xl = xl xor (f(xr) xor p[i + 1])
      i += 2
    }
    block[0] = xr xor p[17]
    block[1] = xl
  }

  private fun f(x: Int): Int {
    val a = s[(x ushr 24) and 0xFF]
    val b = s[256 + ((x ushr 16) and 0xFF)]
    val c = s[512 + ((x ushr 8) and 0xFF)]
    val d = s[768 + (x and 0xFF)]
    return ((a + b) xor c) + d
  }

  /**
   * OpenSSH's `Blowfish_expand0state`: XORs [key] cyclically into `P`, then re-enciphers a chained
   * zero block to overwrite every entry of `P` and every S-box, using the schedule as it stands at
   * each step (each encipher call sees the partially-updated state from the calls before it).
   */
  fun expand0State(key: ByteArray) {
    xorKeyIntoP(key)
    chainIntoScheduleAndBoxes(salt = null)
  }

  /**
   * OpenSSH's `Blowfish_expandstate`: as [expand0State], but also folds [salt] into the chaining.
   */
  fun expandState(salt: ByteArray, key: ByteArray) {
    xorKeyIntoP(key)
    chainIntoScheduleAndBoxes(salt)
  }

  private fun xorKeyIntoP(key: ByteArray) {
    val cursor = intArrayOf(0)
    for (i in p.indices) p[i] = p[i] xor streamWord(key, cursor)
  }

  /** `left`/`right` are plain locals, not captured by a helper closure: Kotlin would box them. */
  private fun chainIntoScheduleAndBoxes(salt: ByteArray?) {
    val saltCursor = intArrayOf(0)
    var left = 0
    var right = 0
    val block = IntArray(2)

    var i = 0
    while (i < p.size) {
      if (salt != null) {
        left = left xor streamWord(salt, saltCursor)
        right = right xor streamWord(salt, saltCursor)
      }
      block[0] = left
      block[1] = right
      encipher(block)
      left = block[0]
      right = block[1]
      p[i] = left
      p[i + 1] = right
      i += 2
    }

    var k = 0
    while (k < s.size) {
      if (salt != null) {
        left = left xor streamWord(salt, saltCursor)
        right = right xor streamWord(salt, saltCursor)
      }
      block[0] = left
      block[1] = right
      encipher(block)
      left = block[0]
      right = block[1]
      s[k] = left
      s[k + 1] = right
      k += 2
    }
  }

  private companion object {
    /** Reads 4 bytes from [data] as a big-endian word, cycling back to the start when exhausted. */
    fun streamWord(data: ByteArray, cursor: IntArray): Int {
      var word = 0
      repeat(4) {
        if (cursor[0] >= data.size) cursor[0] = 0
        word = (word shl 8) or (data[cursor[0]].toInt() and 0xFF)
        cursor[0]++
      }
      return word
    }
  }
}
