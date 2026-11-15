/**
 * Copyright 2026 The kage Authors. All rights reserved. Use of this source code is governed by
 * either an Apache 2.0 or MIT license at your discretion, that can be found in the LICENSE-APACHE
 * or LICENSE-MIT files respectively.
 */
package kage.crypto.mlkem

import com.github.michaelbull.result.getOrThrow
import com.github.michaelbull.result.mapError
import java.security.SecureRandom
import kage.Age
import kage.Identity
import kage.crypto.mlkem.MlKem768X25519Recipient.Companion.MLKEM768X25519_INFO
import kage.crypto.mlkem.MlKem768X25519Recipient.Companion.MLKEM768X25519_STANZA_TYPE
import kage.crypto.stream.ChaCha20Poly1305
import kage.errors.IncorrectCipherTextSizeException
import kage.errors.IncorrectIdentityException
import kage.errors.MlKem768X25519IdentityException
import kage.format.AgeStanza
import kage.format.Bech32
import kage.multiUnwrap
import kage.utils.decodeBase64

/**
 * Decrypts age files with an MLKEM768-X25519 (X-Wing) identity.
 *
 * @param secretKey raw 32-byte seed used to derive the key pair
 */
public class MlKem768X25519Identity(secretKey: ByteArray) : Identity {

  private val secretKey = secretKey.copyOf()
  private val privateKey = MlKem768X25519.newPrivateKey(this.secretKey)

  private fun unwrapSingle(stanza: AgeStanza): ByteArray {
    if (stanza.type != MLKEM768X25519_STANZA_TYPE) throw IncorrectIdentityException()

    if (stanza.args.size != 1)
      throw MlKem768X25519IdentityException("invalid mlkem768x25519 recipient block")

    val enc =
      try {
        stanza.args[0].decodeBase64()
      } catch (err: Exception) {
        throw MlKem768X25519IdentityException("invalid mlkem768x25519 recipient block", err)
      }

    if (enc.size != MlKem768X25519.ENC_SIZE)
      throw MlKem768X25519IdentityException("invalid mlkem768x25519 recipient block")

    // Checked before decrypting to mitigate partitioning oracle attacks.
    if (stanza.body.size != Age.FILE_KEY_SIZE + ChaCha20Poly1305.MAC_SIZE)
      throw IncorrectCipherTextSizeException()

    val sharedSecret = MlKem768X25519.decapsulate(privateKey, enc)

    try {
      return Hpke.open(sharedSecret, MLKEM768X25519_INFO.toByteArray(), stanza.body)
    } catch (err: Exception) {
      throw IncorrectIdentityException(err)
    }
  }

  /**
   * Decrypts the file key from the first stanza this identity can unwrap.
   *
   * @param stanzas recipient stanzas from an age file
   * @return decrypted file key
   */
  override fun unwrap(stanzas: List<AgeStanza>): ByteArray {
    return multiUnwrap(::unwrapSingle, stanzas)
  }

  /** Returns the [MlKem768X25519Recipient] for this identity. */
  public fun recipient(): MlKem768X25519Recipient =
    MlKem768X25519Recipient(MlKem768X25519.publicKey(privateKey))

  /**
   * Encodes this identity as an `AGE-SECRET-KEY-PQ-` Bech32 string.
   *
   * @return Bech32-encoded private key
   */
  public fun encodeToString(): String =
    Bech32.encode(AGE_SECRET_KEY_PQ_PREFIX, secretKey).getOrThrow()

  public companion object {
    internal const val AGE_SECRET_KEY_PQ_PREFIX = "AGE-SECRET-KEY-PQ-"

    /**
     * Decodes an `AGE-SECRET-KEY-PQ-` Bech32 string into an [MlKem768X25519Identity].
     *
     * @param string Bech32-encoded private key
     * @return decoded identity
     */
    public fun decode(string: String): MlKem768X25519Identity {
      val (hrp, key) =
        Bech32.decode(string)
          .mapError { MlKem768X25519IdentityException("Invalid private key", it) }
          .getOrThrow()

      if (hrp != AGE_SECRET_KEY_PQ_PREFIX)
        throw MlKem768X25519IdentityException(
          "Invalid human readable part for age secret key ($hrp)"
        )

      return MlKem768X25519Identity(key)
    }

    /**
     * Generates an [MlKem768X25519Identity] with a random private key.
     *
     * @return new identity
     */
    public fun new(): MlKem768X25519Identity {
      val secretKey = ByteArray(MlKem768X25519.SEED_SIZE)
      SecureRandom().nextBytes(secretKey)

      return MlKem768X25519Identity(secretKey)
    }
  }
}
