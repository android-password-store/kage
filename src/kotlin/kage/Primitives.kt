package kage

import at.favre.lib.crypto.HKDF
import kage.format.AgeHeader
import java.io.ByteArrayOutputStream
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

internal object Primitives {

  private const val MAC_ALGORITHM = "HmacSHA256"
  private const val MAC_KEY_LENGTH = 32
  private const val CHACHA_20_POLY_1305_KEY_LENGTH = 32

  fun headerMAC(fileKey: ByteArray, header: AgeHeader): ByteArray {
    // Passing null directly in extractAndExpand causes overload ambiguity since both SecretKey and ByteArray can be null
    // so create a null variable of type ByteArray
    val saltExtract: ByteArray? = null
    val headerByteArray = "header".encodeToByteArray()
    val hkdf = HKDF.fromHmacSha256()

    val hmacKey = hkdf.extractAndExpand(saltExtract, fileKey, headerByteArray, MAC_KEY_LENGTH)
    val secretKey = SecretKeySpec(hmacKey, MAC_ALGORITHM)

    val mac = Mac.getInstance(MAC_ALGORITHM)
    mac.init(secretKey)

    val outputStream = ByteArrayOutputStream()
    outputStream.bufferedWriter().use { writer ->
      AgeHeader.writeWithoutMac(writer, header)
    }

    // Here we need to pass the complete header including the footer prefix
    return mac.doFinal(outputStream.toByteArray())
  }

  fun streamKey(fileKey: ByteArray, nonce: ByteArray): ByteArray {
    val payloadByteArray = "payload".encodeToByteArray()
    val hkdf = HKDF.fromHmacSha256()
    return hkdf.extractAndExpand(nonce, fileKey, payloadByteArray, CHACHA_20_POLY_1305_KEY_LENGTH)
  }
}