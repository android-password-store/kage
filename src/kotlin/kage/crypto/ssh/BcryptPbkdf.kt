/**
 * Copyright 2022 The kage Authors. All rights reserved. Use of this source code is governed by
 * either an Apache 2.0 or MIT license at your discretion, that can be found in the LICENSE-APACHE
 * or LICENSE-MIT files respectively.
 */
package kage.crypto.ssh

import org.bouncycastle.crypto.generators.BCrypt

/**
 * OpenSSH's `bcrypt_pbkdf`: the KDF a passphrase-encrypted OpenSSH private key uses (`kdfname
 * "bcrypt"`) to turn a passphrase into the key/IV that unlocks the private key section.
 */
internal object BcryptPbkdf {
  private const val MAX_KEY_LENGTH = 1024 // 32-byte bcrypt output times 32 interleaved blocks

  /**
   * Derives [keyLength] bytes from [password] and [salt] over [rounds] stretching rounds. Throws
   * [IllegalArgumentException] on bad arguments.
   */
  fun derive(password: ByteArray, salt: ByteArray, keyLength: Int, rounds: Int): ByteArray {
    require(rounds >= 1) { "rounds must be >= 1, was $rounds" }
    require(password.isNotEmpty()) { "password must not be empty" }
    require(salt.isNotEmpty()) { "salt must not be empty" }
    require(keyLength in 1..MAX_KEY_LENGTH) {
      "keyLength must be in 1..$MAX_KEY_LENGTH, was $keyLength"
    }

    return BCrypt.pbkdfGenerate(password, salt, rounds, keyLength)
  }
}
