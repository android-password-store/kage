/**
 * Copyright 2021 The kage Authors. All rights reserved.
 * Use of this source code is governed by either an
 * Apache 2.0 or MIT license at your discretion, that can
 * be found in the LICENSE-APACHE or LICENSE-MIT files
 * respectively.
 */
package kage

import at.favre.lib.crypto.HKDF
import java.io.ByteArrayOutputStream
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec
import kage.format.AgeHeader

internal object Primitives {

  private const val MAC_ALGORITHM = "HmacSHA256"
  private const val MAC_KEY_LENGTH = 32
  private const val CHACHA_20_POLY_1305_KEY_LENGTH = 32
  private const val HEADER_INFO = "header"
  private const val PAYLOAD_INFO = "payload"

  fun headerMAC(fileKey: ByteArray, header: AgeHeader): ByteArray {
    // Passing null directly in extractAndExpand causes overload ambiguity since both SecretKey and
    // ByteArray can be null so create a null variable of type ByteArray
    val saltExtract: ByteArray? = null
    val headerByteArray = HEADER_INFO.encodeToByteArray()
    val hkdf = HKDF.fromHmacSha256()

    val hmacKey = hkdf.extractAndExpand(saltExtract, fileKey, headerByteArray, MAC_KEY_LENGTH)
    val secretKey = SecretKeySpec(hmacKey, MAC_ALGORITHM)

    val mac = Mac.getInstance(MAC_ALGORITHM)
    mac.init(secretKey)

    val outputStream = ByteArrayOutputStream()
    outputStream.bufferedWriter().use { writer -> AgeHeader.writeWithoutMac(writer, header) }

    // Here we need to pass the complete header including the footer prefix
    return mac.doFinal(outputStream.toByteArray())
  }

  fun streamKey(fileKey: ByteArray, nonce: ByteArray): ByteArray {
    val payloadByteArray = PAYLOAD_INFO.encodeToByteArray()
    val hkdf = HKDF.fromHmacSha256()
    return hkdf.extractAndExpand(nonce, fileKey, payloadByteArray, CHACHA_20_POLY_1305_KEY_LENGTH)
  }
}
