/**
 * Copyright 2026 The kage Authors. All rights reserved. Use of this source code is governed by
 * either an Apache 2.0 or MIT license at your discretion, that can be found in the LICENSE-APACHE
 * or LICENSE-MIT files respectively.
 */
package kage.crypto.mlkem

import com.github.michaelbull.result.getOrThrow
import com.github.michaelbull.result.mapError
import kage.Recipient
import kage.RecipientWithLabels
import kage.errors.InvalidRecipientException
import kage.format.AgeStanza
import kage.format.Bech32
import kage.utils.encodeBase64

/**
 * An age recipient backed by an MLKEM768-X25519 (X-Wing) public key.
 *
 * @param publicKey Raw public key, an ML-KEM-768 encapsulation key followed by an X25519 public
 *   key.
 */
public class MlKem768X25519Recipient(publicKey: ByteArray) : Recipient, RecipientWithLabels {

  private val publicKey = publicKey.copyOf().also(MlKem768X25519::validatePublicKey)

  override fun wrap(fileKey: ByteArray): List<AgeStanza> = wrapWithLabels(fileKey).first

  override fun wrapWithLabels(fileKey: ByteArray): Pair<List<AgeStanza>, List<String>> {
    val (sharedSecret, enc) = MlKem768X25519.encapsulate(publicKey)

    val wrappedKey = Hpke.seal(sharedSecret, MLKEM768X25519_INFO.toByteArray(), fileKey)

    val stanza = AgeStanza(MLKEM768X25519_STANZA_TYPE, listOf(enc.encodeBase64()), wrappedKey)

    return Pair(listOf(stanza), listOf(POST_QUANTUM_LABEL))
  }

  /** Encodes this recipient as an `age1pq1...` Bech32 public key. */
  public fun encodeToString(): String =
    Bech32.encode(AGE_PUBLIC_KEY_PQ_PREFIX, publicKey).getOrThrow()

  public companion object {
    internal const val MLKEM768X25519_STANZA_TYPE = "mlkem768x25519"
    internal const val MLKEM768X25519_INFO = "age-encryption.org/mlkem768x25519"
    internal const val AGE_PUBLIC_KEY_PQ_PREFIX = "age1pq"
    internal const val POST_QUANTUM_LABEL = "postquantum"

    /** Decodes an `age1pq1...` Bech32 public key into an MLKEM768-X25519 recipient. */
    public fun decode(string: String): MlKem768X25519Recipient {
      val (hrp, key) =
        Bech32.decode(string)
          .mapError { InvalidRecipientException("Invalid public key", it) }
          .getOrThrow()

      if (key.size != MlKem768X25519.PUBLIC_KEY_SIZE)
        throw InvalidRecipientException("Invalid key size for age public key (${key.size})")

      if (hrp != AGE_PUBLIC_KEY_PQ_PREFIX)
        throw InvalidRecipientException("Invalid human readable part for age public key ($hrp)")

      return MlKem768X25519Recipient(key)
    }
  }
}
