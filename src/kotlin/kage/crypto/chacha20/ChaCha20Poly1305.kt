/**
 * Copyright 2021 The kage Authors. All rights reserved. Use of this source code is governed by
 * either an Apache 2.0 or MIT license at your discretion, that can be found in the LICENSE-APACHE
 * or LICENSE-MIT files respectively.
 */
package kage.crypto.chacha20

import org.bouncycastle.crypto.modes.ChaCha20Poly1305
import org.bouncycastle.crypto.params.AEADParameters
import org.bouncycastle.crypto.params.KeyParameter

public object ChaCha20Poly1305 {
  private const val MAC_SIZE: Int = 16 // bytes
  public const val CHACHA_20_POLY_1305_KEY_LENGTH: Int = 32 // bytes
  public const val CHACHA_20_POLY_1305_NONCE_LENGTH: Int = 12 // bytes

  public fun encrypt(
    key: ByteArray,
    nonce: ByteArray,
    input: ByteArray,
    inOff: Int,
    inLen: Int
  ): ByteArray {
    val cipher = ChaCha20Poly1305()
    val secKey = KeyParameter(key)
    val params = AEADParameters(secKey, MAC_SIZE * 8, nonce)

    cipher.init(true, params)

    val output = ByteArray(cipher.getOutputSize(inLen))

    val c = cipher.processBytes(input, inOff, inLen, output, 0)
    cipher.doFinal(output, c)

    return output
  }

  public fun encrypt(key: ByteArray, nonce: ByteArray, input: ByteArray): ByteArray {
    return encrypt(key, nonce, input, 0, input.size)
  }

  public fun decrypt(input: ByteArray, key: ByteArray, nonce: ByteArray): ByteArray {
    val cipher = ChaCha20Poly1305()
    val secKey = KeyParameter(key)
    val params = AEADParameters(secKey, MAC_SIZE * 8, nonce)

    cipher.init(false, params)

    val output = ByteArray(cipher.getOutputSize(input.size))

    val c = cipher.processBytes(input, 0, input.size, output, 0)
    cipher.doFinal(output, c)

    return output
  }
}
