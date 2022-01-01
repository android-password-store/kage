package kage

import at.favre.lib.crypto.HKDF
import kage.format.AgeHeader
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

internal object Primitives {
  fun headerMAC(fileKey: ByteArray, header: AgeHeader): ByteArray {
    val hmacAlgorithm = "HmacSHA256"
    val headerByteArray = "header".encodeToByteArray()
    val hkdf = HKDF.fromHmacSha256()
    // Passing null directly in extractAndExpand causes overload ambiguity since both SecretKey and ByteArray can be null
    // so create a null variable of type ByteArray
    val saltExtract: ByteArray? = null

    val hmacKey = hkdf.extractAndExpand(saltExtract, fileKey, headerByteArray, 32)
    val secretKey = SecretKeySpec(hmacKey, hmacAlgorithm)

    val mac = Mac.getInstance(hmacAlgorithm)
    mac.init(secretKey)

    val outputStream = ByteArrayOutputStream()
    outputStream.bufferedWriter().use { writer ->
      AgeHeader.writeWithoutMac(writer, header)
    }

    // Here we need to pass the complete header including the footer prefix
    return mac.doFinal(outputStream.toByteArray())
  }
}