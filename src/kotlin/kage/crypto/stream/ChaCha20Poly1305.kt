/**
 * Copyright 2022 The kage Authors. All rights reserved. Use of this source code is governed by
 * either an Apache 2.0 or MIT license at your discretion, that can be found in the LICENSE-APACHE
 * or LICENSE-MIT files respectively.
 */
package kage.crypto.stream

import kage.errors.IncorrectCipherTextSizeException
import kotlin.math.max
import org.bouncycastle.crypto.modes.ChaCha20Poly1305
import org.bouncycastle.crypto.params.AEADParameters
import org.bouncycastle.crypto.params.KeyParameter

internal object ChaCha20Poly1305 {
  const val MAC_SIZE: Int = 16 // bytes
  const val KEY_LENGTH: Int = 32 // bytes
  const val NONCE_LENGTH: Int = 12 // bytes

  fun encrypt(
    key: ByteArray,
    nonce: ByteArray,
    input: ByteArray,
    inOff: Int,
    inLen: Int,
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

  fun aeadEncrypt(key: ByteArray, input: ByteArray): ByteArray {
    // From the spec: https://github.com/C2SP/C2SP/blob/main/age.md
    // "ChaCha20-Poly1305 nonce is fixed as 12 0x00 bytes [...]"
    val nonce = ByteArray(NONCE_LENGTH)

    return encrypt(key, nonce, input, 0, input.size)
  }

  fun decrypt(
    key: ByteArray,
    nonce: ByteArray,
    input: ByteArray,
    inOff: Int,
    inLen: Int,
    out: ByteArray,
    outOff: Int
  ): Int {
    val cipher = ChaCha20Poly1305()
    val secKey = KeyParameter(key)
    val params = AEADParameters(secKey, MAC_SIZE * 8, nonce)

    cipher.init(false, params)

    var outputSize = 0

    outputSize += cipher.processBytes(input, inOff, inLen, out, outOff)
    outputSize += cipher.doFinal(out, outputSize)

    return outputSize
  }

  /**
   * From age.go:
   *
   * The message size is limited to mitigate multi-key attacks, where a ciphertext can be crafted
   * that decrypts successfully under multiple keys. Short ciphertexts can only target two keys,
   * which has limited impact.
   */
  fun aeadDecrypt(key: ByteArray, input: ByteArray, expectedPlaintextSize: Int): ByteArray {
    val out = ByteArray(max(0, input.size - MAC_SIZE))

    val nonce = ByteArray(NONCE_LENGTH)

    if (input.size != expectedPlaintextSize + MAC_SIZE) throw IncorrectCipherTextSizeException()

    decrypt(key, nonce, input, 0, input.size, out, 0)

    return out
  }
}
