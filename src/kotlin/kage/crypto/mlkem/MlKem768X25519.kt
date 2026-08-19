/**
 * Copyright 2026 The kage Authors. All rights reserved. Use of this source code is governed by
 * either an Apache 2.0 or MIT license at your discretion, that can be found in the LICENSE-APACHE
 * or LICENSE-MIT files respectively.
 */
package kage.crypto.mlkem

import java.security.SecureRandom
import kage.crypto.x25519.X25519
import kage.errors.InvalidRecipientException
import kage.errors.MlKem768X25519IdentityException
import kage.errors.X25519LowOrderPointException
import org.bouncycastle.crypto.digests.SHA3Digest
import org.bouncycastle.crypto.digests.SHAKEDigest
import org.bouncycastle.crypto.kems.MLKEMExtractor
import org.bouncycastle.crypto.kems.MLKEMGenerator
import org.bouncycastle.crypto.params.MLKEMParameters
import org.bouncycastle.crypto.params.MLKEMPrivateKeyParameters
import org.bouncycastle.crypto.params.MLKEMPublicKeyParameters
import org.bouncycastle.math.ec.rfc7748.X25519.POINT_SIZE

/** The MLKEM768-X25519 (X-Wing) hybrid KEM used by the age post-quantum recipient type. */
internal object MlKem768X25519 {
  const val SEED_SIZE = 32 // bytes
  const val ENCAPSULATION_KEY_SIZE = 1184 // bytes
  const val CIPHER_TEXT_SIZE = 1088 // bytes
  const val PUBLIC_KEY_SIZE = ENCAPSULATION_KEY_SIZE + POINT_SIZE
  const val ENC_SIZE = CIPHER_TEXT_SIZE + POINT_SIZE

  private const val ML_KEM_SEED_SIZE = 64 // bytes, FIPS 203 (d || z)

  // The combiner label is the `\./` `/^\` ASCII art from filippo.io/hpke, spelled out as raw bytes
  // so that no escaping is involved.
  private val COMBINER_LABEL = byteArrayOf(0x5C, 0x2E, 0x2F, 0x2F, 0x5E, 0x5C)

  /** An MLKEM768-X25519 private key expanded from a 32 byte identity seed. */
  class PrivateKey(
    val mlKem: MLKEMPrivateKeyParameters,
    val x25519: ByteArray,
    val x25519PublicKey: ByteArray,
  )

  /**
   * Expands [seed] into an MLKEM768-X25519 private key.
   *
   * Both sub-keys are drawn from a single SHAKE256 stream keyed with [seed]: 64 bytes for the
   * ML-KEM seed first, then 32 bytes for the X25519 scalar. X25519 accepts any 32 byte scalar, so
   * the retry loop of the reference implementation is not needed here.
   */
  fun newPrivateKey(seed: ByteArray): PrivateKey {
    if (seed.size != SEED_SIZE)
      throw MlKem768X25519IdentityException(
        "Invalid MLKEM768-X25519 private key size: (${seed.size})"
      )

    val shake = SHAKEDigest(256)
    shake.update(seed, 0, seed.size)

    val mlKemSeed = ByteArray(ML_KEM_SEED_SIZE)
    shake.doOutput(mlKemSeed, 0, mlKemSeed.size)

    val x25519Seed = ByteArray(POINT_SIZE)
    shake.doOutput(x25519Seed, 0, x25519Seed.size)

    return PrivateKey(
      MLKEMPrivateKeyParameters(MLKEMParameters.ml_kem_768, mlKemSeed),
      x25519Seed,
      X25519.scalarMultBase(x25519Seed),
    )
  }

  fun publicKey(privateKey: PrivateKey): ByteArray =
    privateKey.mlKem.publicKey.plus(privateKey.x25519PublicKey)

  /** Rejects malformed ML-KEM and low-order X25519 public key components. */
  fun validatePublicKey(publicKey: ByteArray) {
    if (publicKey.size != PUBLIC_KEY_SIZE)
      throw InvalidRecipientException("Invalid key size for age public key (${publicKey.size})")

    try {
      MLKEMPublicKeyParameters(
        MLKEMParameters.ml_kem_768,
        publicKey.copyOfRange(0, ENCAPSULATION_KEY_SIZE),
      )
      X25519.scalarMult(
        ByteArray(POINT_SIZE),
        publicKey.copyOfRange(ENCAPSULATION_KEY_SIZE, publicKey.size),
      )
    } catch (err: IllegalArgumentException) {
      throw InvalidRecipientException("Invalid ML-KEM public key", err)
    } catch (err: X25519LowOrderPointException) {
      throw InvalidRecipientException("Invalid X25519 public key", err)
    }
  }

  /** Returns the shared secret and the encapsulated key for [publicKey]. */
  fun encapsulate(publicKey: ByteArray): Pair<ByteArray, ByteArray> {
    if (publicKey.size != PUBLIC_KEY_SIZE)
      throw InvalidRecipientException("Invalid key size for age public key (${publicKey.size})")

    val mlKemPublicKey =
      MLKEMPublicKeyParameters(
        MLKEMParameters.ml_kem_768,
        publicKey.copyOfRange(0, ENCAPSULATION_KEY_SIZE),
      )
    val x25519PublicKey = publicKey.copyOfRange(ENCAPSULATION_KEY_SIZE, publicKey.size)

    val encapsulated = MLKEMGenerator(SecureRandom()).generateEncapsulated(mlKemPublicKey)

    val ephemeralSecret = ByteArray(POINT_SIZE)
    SecureRandom().nextBytes(ephemeralSecret)

    val ephemeralShare = X25519.scalarMultBase(ephemeralSecret)
    val x25519Secret = X25519.scalarMult(ephemeralSecret, x25519PublicKey)

    val sharedSecret =
      sharedSecret(encapsulated.secret, x25519Secret, ephemeralShare, x25519PublicKey)

    return Pair(sharedSecret, encapsulated.encapsulation.plus(ephemeralShare))
  }

  /** Returns the shared secret for the [ENC_SIZE] byte encapsulated key [enc]. */
  fun decapsulate(privateKey: PrivateKey, enc: ByteArray): ByteArray {
    val mlKemCipherText = enc.copyOfRange(0, CIPHER_TEXT_SIZE)
    val ephemeralShare = enc.copyOfRange(CIPHER_TEXT_SIZE, enc.size)

    val mlKemSecret = MLKEMExtractor(privateKey.mlKem).extractSecret(mlKemCipherText)
    val x25519Secret = X25519.scalarMult(privateKey.x25519, ephemeralShare)

    return sharedSecret(mlKemSecret, x25519Secret, ephemeralShare, privateKey.x25519PublicKey)
  }

  private fun sharedSecret(
    mlKemSecret: ByteArray,
    x25519Secret: ByteArray,
    ephemeralShare: ByteArray,
    x25519PublicKey: ByteArray,
  ): ByteArray {
    val digest = SHA3Digest(256)
    digest.update(mlKemSecret, 0, mlKemSecret.size)
    digest.update(x25519Secret, 0, x25519Secret.size)
    digest.update(ephemeralShare, 0, ephemeralShare.size)
    digest.update(x25519PublicKey, 0, x25519PublicKey.size)
    digest.update(COMBINER_LABEL, 0, COMBINER_LABEL.size)

    val out = ByteArray(digest.digestSize)
    digest.doFinal(out, 0)
    return out
  }
}
