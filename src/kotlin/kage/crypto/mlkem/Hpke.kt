/**
 * Copyright 2026 The kage Authors. All rights reserved. Use of this source code is governed by
 * either an Apache 2.0 or MIT license at your discretion, that can be found in the LICENSE-APACHE
 * or LICENSE-MIT files respectively.
 */
package kage.crypto.mlkem

import at.favre.lib.hkdf.HKDF
import kage.crypto.stream.ChaCha20Poly1305

/**
 * RFC 9180 HPKE in base mode, restricted to the single cipher suite the age MLKEM768-X25519
 * recipient type uses: MLKEM768-X25519 / HKDF-SHA256 / ChaCha20Poly1305.
 *
 * age seals exactly one message per stanza, so the sequence number is always zero and the base
 * nonce is used as-is.
 */
internal object Hpke {
  private const val VERSION_LABEL = "HPKE-v1"
  private const val KEM_ID = 0x647a
  private const val KDF_ID = 0x0001
  private const val AEAD_ID = 0x0003
  private const val MODE_BASE: Byte = 0x00

  private val SUITE_ID =
    "HPKE".toByteArray().plus(bigEndian(KEM_ID)).plus(bigEndian(KDF_ID)).plus(bigEndian(AEAD_ID))

  fun seal(sharedSecret: ByteArray, info: ByteArray, plainText: ByteArray): ByteArray {
    val (key, nonce) = keySchedule(sharedSecret, info)
    return ChaCha20Poly1305.encrypt(key, nonce, plainText, 0, plainText.size)
  }

  fun open(sharedSecret: ByteArray, info: ByteArray, cipherText: ByteArray): ByteArray {
    val (key, nonce) = keySchedule(sharedSecret, info)
    val out = ByteArray(cipherText.size - ChaCha20Poly1305.MAC_SIZE)
    ChaCha20Poly1305.decrypt(key, nonce, cipherText, 0, cipherText.size, out, 0)
    return out
  }

  private fun keySchedule(sharedSecret: ByteArray, info: ByteArray): Pair<ByteArray, ByteArray> {
    val pskIdHash = labeledExtract(null, "psk_id_hash", ByteArray(0))
    val infoHash = labeledExtract(null, "info_hash", info)
    val context = byteArrayOf(MODE_BASE).plus(pskIdHash).plus(infoHash)

    val secret = labeledExtract(sharedSecret, "secret", ByteArray(0))

    return Pair(
      labeledExpand(secret, "key", context, ChaCha20Poly1305.KEY_LENGTH),
      labeledExpand(secret, "base_nonce", context, ChaCha20Poly1305.NONCE_LENGTH),
    )
  }

  private fun labeledExtract(salt: ByteArray?, label: String, ikm: ByteArray): ByteArray =
    HKDF.fromHmacSha256()
      .extract(salt, VERSION_LABEL.toByteArray().plus(SUITE_ID).plus(label.toByteArray()).plus(ikm))

  private fun labeledExpand(
    prk: ByteArray,
    label: String,
    info: ByteArray,
    length: Int,
  ): ByteArray =
    HKDF.fromHmacSha256()
      .expand(
        prk,
        bigEndian(length)
          .plus(VERSION_LABEL.toByteArray())
          .plus(SUITE_ID)
          .plus(label.toByteArray())
          .plus(info),
        length,
      )

  private fun bigEndian(value: Int): ByteArray =
    byteArrayOf((value ushr 8).toByte(), value.toByte())
}
