/**
 * Copyright 2022 The kage Authors. All rights reserved. Use of this source code is governed by
 * either an Apache 2.0 or MIT license at your discretion, that can be found in the LICENSE-APACHE
 * or LICENSE-MIT files respectively.
 */
package kage

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.io.OutputStream
import java.security.MessageDigest
import java.security.SecureRandom
import kage.crypto.scrypt.ScryptRecipient
import kage.crypto.stream.DecryptInputStream
import kage.crypto.stream.EncryptOutputStream
import kage.errors.IncorrectIdentityException
import kage.errors.InvalidScryptRecipientException
import kage.errors.NoIdentitiesException
import kage.errors.NoRecipientsException
import kage.errors.StreamException
import kage.format.AgeFile
import kage.format.AgeHeader

public object Age {
  internal const val FILE_KEY_SIZE: Int = 16
  private const val STREAM_NONCE_SIZE = 16

  @JvmStatic
  public fun encryptStream(
    recipients: List<Recipient>,
    inputStream: InputStream,
    outputStream: OutputStream,
    generateArmor: Boolean = false
  ) {
    if (generateArmor) TODO("not implemented")

    val (_, stream) = encryptInternal(recipients, outputStream)

    stream.use { output -> inputStream.use { input -> input.copyTo(output) } }
  }

  @JvmStatic
  public fun encrypt(recipients: List<Recipient>, plainText: InputStream): AgeFile {
    val out = ByteArrayOutputStream()

    val (header, stream) = encryptInternal(recipients, out, writeHeaders = false)

    stream.use { output -> plainText.use { input -> input.copyTo(output) } }

    return AgeFile(header, out.toByteArray())
  }

  @JvmStatic
  public fun decryptStream(
    identities: List<Identity>,
    srcStream: InputStream,
    dstStream: OutputStream
  ) {
    val ageFile = AgeFile.parse(srcStream)

    val input = decryptInternal(identities, ageFile)

    input.use { src -> dstStream.use { dst -> src.copyTo(dst) } }
  }

  @JvmStatic
  public fun decrypt(identities: List<Identity>, ageFile: AgeFile): InputStream =
    decryptInternal(identities, ageFile)

  @JvmStatic
  public fun decrypt(identity: Identity, ageFile: AgeFile): InputStream =
    decryptInternal(listOf(identity), ageFile)

  private fun encryptInternal(
    recipients: List<Recipient>,
    dst: OutputStream,
    writeHeaders: Boolean = true
  ): Pair<AgeHeader, OutputStream> {
    if (recipients.isEmpty()) {
      throw NoRecipientsException("No recipients specified")
    }

    // From the age docs:
    // As a best effort, prevent an API user from generating a file that the
    // ScryptIdentity will refuse to decrypt. This check can't unfortunately be
    // implemented as part of the Recipient interface, so it lives as a special
    // case in Encrypt.
    // https://github.com/FiloSottile/age/blob/ab3707c085f2c1fdfd767a2ed718423e3925f4c4/age.go#L114-L122
    recipients.forEach { recipient ->
      if (recipient is ScryptRecipient && recipients.size != 1) {
        throw InvalidScryptRecipientException("Only one scrypt recipient is supported")
      }
    }

    val fileKey = generateFileKey()

    val stanzas = recipients.flatMap { recipient -> recipient.wrap(fileKey) }

    // TODO: Check if we need a deep copy of stanzas here
    val ageHeader = AgeHeader.withMac(stanzas, fileKey)

    val nonce = ByteArray(STREAM_NONCE_SIZE)
    SecureRandom().nextBytes(nonce)

    if (writeHeaders) {
      val writer = dst.bufferedWriter()
      AgeHeader.write(writer, ageHeader)
      // Need to flush the wrapping stream before writing again to the underlying stream
      writer.flush()
    }

    dst.write(nonce)

    val streamKey = Primitives.streamKey(fileKey, nonce)

    return Pair(ageHeader, EncryptOutputStream(streamKey, dst))
  }

  private fun generateFileKey(): ByteArray {
    val fileKey = ByteArray(FILE_KEY_SIZE)
    SecureRandom().nextBytes(fileKey)
    return fileKey
  }

  private fun decryptInternal(identities: List<Identity>, ageFile: AgeFile): InputStream {
    if (identities.isEmpty()) throw NoIdentitiesException("no identities specified")

    val lastError = IncorrectIdentityException()

    for (identity in identities) {
      val fileKey =
        try {
          identity.unwrap(ageFile.header.recipients)
        } catch (err: IncorrectIdentityException) {
          lastError.addSuppressed(err)
          continue
        }

      val calculatedMac = Primitives.headerMAC(fileKey, ageFile.header)

      if (!MessageDigest.isEqual(ageFile.header.mac, calculatedMac))
        throw StreamException("bad header MAC")

      val nonce = ByteArray(STREAM_NONCE_SIZE)
      ageFile.body.copyInto(nonce, 0, 0, STREAM_NONCE_SIZE)

      val streamKey = Primitives.streamKey(fileKey, nonce)

      val bis = ByteArrayInputStream(ageFile.body)
      bis.skip(STREAM_NONCE_SIZE.toLong())

      return DecryptInputStream(streamKey, bis)
    }

    throw lastError
  }
}
