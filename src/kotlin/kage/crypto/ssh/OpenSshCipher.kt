/**
 * Copyright 2022 The kage Authors. All rights reserved. Use of this source code is governed by
 * either an Apache 2.0 or MIT license at your discretion, that can be found in the LICENSE-APACHE
 * or LICENSE-MIT files respectively.
 */
package kage.crypto.ssh

import kage.errors.UnsupportedSshKeyException
import org.bouncycastle.crypto.BufferedBlockCipher
import org.bouncycastle.crypto.engines.AESEngine
import org.bouncycastle.crypto.modes.CBCBlockCipher
import org.bouncycastle.crypto.modes.SICBlockCipher
import org.bouncycastle.crypto.params.KeyParameter
import org.bouncycastle.crypto.params.ParametersWithIV

/**
 * The OpenSSH private-key-file ciphers `ssh-keygen` actually produces: AES in CTR mode (the current
 * default, since OpenSSH 6.5) and AES in CBC mode (the default before that). Every one of them uses
 * a 16-byte IV regardless of key size, since that's the AES block size, not the key size.
 */
internal object OpenSshCipher {
  private data class Spec(val keySize: Int, val mode: Mode)

  private enum class Mode {
    CTR,
    CBC,
  }

  private const val AES_BLOCK_SIZE = 16

  private val CIPHERS =
    mapOf(
      "aes128-ctr" to Spec(16, Mode.CTR),
      "aes192-ctr" to Spec(24, Mode.CTR),
      "aes256-ctr" to Spec(32, Mode.CTR),
      "aes128-cbc" to Spec(16, Mode.CBC),
      "aes192-cbc" to Spec(24, Mode.CBC),
      "aes256-cbc" to Spec(32, Mode.CBC),
    )

  /** Combined key+IV length [BcryptPbkdf.derive] must produce to decrypt with [cipherName]. */
  fun keyAndIvLength(cipherName: String): Int = spec(cipherName).keySize + AES_BLOCK_SIZE

  /**
   * Decrypts [ciphertext] (the OpenSSH private key's encrypted section, always a whole multiple of
   * the AES block size) using [cipherName] with the leading [keyAndIvLength] bytes of [keyAndIv] as
   * key and the rest as IV.
   */
  fun decrypt(cipherName: String, keyAndIv: ByteArray, ciphertext: ByteArray): ByteArray {
    val cipherSpec = spec(cipherName)
    val key = keyAndIv.copyOfRange(0, cipherSpec.keySize)
    val iv = keyAndIv.copyOfRange(cipherSpec.keySize, cipherSpec.keySize + AES_BLOCK_SIZE)

    val blockCipher =
      when (cipherSpec.mode) {
        Mode.CTR -> SICBlockCipher.newInstance(AESEngine.newInstance())
        Mode.CBC -> CBCBlockCipher.newInstance(AESEngine.newInstance())
      }
    blockCipher.init(false, ParametersWithIV(KeyParameter(key), iv))

    // No padding scheme: OpenSSH pads the plaintext itself (1, 2, 3, ...) before encrypting, and
    // the caller validates that against the key's own field lengths.
    val buffered = BufferedBlockCipher(blockCipher)
    val out = ByteArray(buffered.getOutputSize(ciphertext.size))
    var len = buffered.processBytes(ciphertext, 0, ciphertext.size, out, 0)
    len += buffered.doFinal(out, len)
    return if (len == out.size) out else out.copyOf(len)
  }

  private fun spec(cipherName: String): Spec =
    CIPHERS[cipherName]
      ?: throw UnsupportedSshKeyException("unsupported OpenSSH private key cipher: $cipherName")
}
