/**
 * Copyright 2022 The kage Authors. All rights reserved. Use of this source code is governed by
 * either an Apache 2.0 or MIT license at your discretion, that can be found in the LICENSE-APACHE
 * or LICENSE-MIT files respectively.
 */
package kage

import java.io.BufferedInputStream
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.io.OutputStream
import java.security.MessageDigest
import java.security.SecureRandom
import kage.crypto.scrypt.ScryptRecipient
import kage.crypto.stream.ArmorInputStream
import kage.crypto.stream.ArmorOutputStream
import kage.crypto.stream.DecryptInputStream
import kage.crypto.stream.EncryptOutputStream
import kage.errors.IncorrectHMACException
import kage.errors.InvalidHMACHeaderException
import kage.errors.InvalidNonceException
import kage.errors.InvalidScryptRecipientException
import kage.errors.NoIdentitiesException
import kage.errors.NoRecipientsException
import kage.errors.ScryptIdentityException
import kage.format.AgeFile
import kage.format.AgeHeader
import kage.format.AgeStanza

/** Encrypts and decrypts data using the age file format. */
public object Age {
  internal const val FILE_KEY_SIZE: Int = 16
  private const val STREAM_NONCE_SIZE = 16
  private const val HMAC_SIZE = 32

  /**
   * Starts encrypting data for [recipients] to [outputStream].
   *
   * Write plaintext to the returned stream, then close it to finish the encrypted payload and close
   * [outputStream]. Set [generateArmor] to emit ASCII-armored ciphertext.
   */
  @JvmStatic
  public fun encryptStream(
    recipients: List<Recipient>,
    outputStream: OutputStream,
    generateArmor: Boolean = false,
  ): OutputStream {
    val dstStream = if (generateArmor) ArmorOutputStream(outputStream) else outputStream

    val (_, stream) = encryptInternal(recipients, dstStream)

    return stream
  }

  /**
   * Encrypts all data from [inputStream] for [recipients] and writes it to [outputStream].
   *
   * After encryption setup succeeds, this method closes both streams. Set [generateArmor] to emit
   * ASCII-armored ciphertext.
   */
  @JvmStatic
  public fun encryptStream(
    recipients: List<Recipient>,
    inputStream: InputStream,
    outputStream: OutputStream,
    generateArmor: Boolean = false,
  ) {
    encryptStream(recipients, outputStream, generateArmor).use { output ->
      inputStream.use { input -> input.copyTo(output) }
    }
  }

  /**
   * Encrypts [plainText] for [recipients] and returns the resulting in-memory age file.
   *
   * After encryption setup succeeds, this method closes [plainText]. Prefer [encryptStream] for
   * large plaintexts.
   */
  @JvmStatic
  public fun encrypt(recipients: List<Recipient>, plainText: InputStream): AgeFile {
    val out = ByteArrayOutputStream()

    val (header, stream) = encryptInternal(recipients, out, writeHeaders = false)

    stream.use { output -> plainText.use { input -> input.copyTo(output) } }

    return AgeFile(header, out.toByteArray())
  }

  /**
   * Decrypts an age stream using one of [identities] and writes the plaintext to [dstStream].
   *
   * Both binary and ASCII-armored ciphertext are accepted. This method closes [dstStream] after
   * writing the plaintext.
   */
  @JvmStatic
  public fun decryptStream(
    identities: List<Identity>,
    srcStream: InputStream,
    dstStream: OutputStream,
  ) {
    // Parse only the header, then stream the payload — avoids buffering the whole body in memory.
    decryptStreamInternal(identities, decodeArmor(srcStream).buffered(), dstStream)
  }

  /**
   * Returns a stream that decrypts [ageFile] with one of [identities].
   *
   * Close the returned stream when finished. Prefer [decryptStream] when the ciphertext is already
   * available as a stream.
   */
  @JvmStatic
  public fun decrypt(identities: List<Identity>, ageFile: AgeFile): InputStream =
    decryptInternal(identities, ageFile)

  /** Returns a stream that decrypts [ageFile] with [identity]. */
  @JvmStatic
  public fun decrypt(identity: Identity, ageFile: AgeFile): InputStream =
    decryptInternal(listOf(identity), ageFile)

  /**
   * Returns the detached header of the age file in [srcStream], leaving its payload untouched.
   *
   * Both binary and ASCII-armored ciphertext are accepted, and the header is always returned in its
   * binary form. The detached header can be decrypted with [decryptHeader], for example on a
   * different system, without sharing the payload.
   *
   * This is a low-level method that most users won't need.
   */
  @JvmStatic
  public fun extractHeader(srcStream: InputStream): ByteArray {
    val header = AgeHeader.parse(decodeArmor(srcStream).buffered())

    val out = ByteArrayOutputStream()
    out.bufferedWriter().use { writer -> header.write(writer) }

    return out.toByteArray()
  }

  /**
   * Decrypts a detached [header] produced by [extractHeader] with one of [identities] and returns
   * the file key it wraps.
   *
   * The file key can be handed to [InjectedFileKeyIdentity] to decrypt the corresponding payload.
   * It is the caller's responsibility to keep track of which file the returned key decrypts, and to
   * ensure it is not used for any other purpose.
   *
   * This is a low-level method that most users won't need.
   */
  @JvmStatic
  public fun decryptHeader(header: ByteArray, identities: List<Identity>): ByteArray =
    resolveFileKey(identities, AgeHeader.parse(ByteArrayInputStream(header).buffered()))

  private fun encryptInternal(
    recipients: List<Recipient>,
    dst: OutputStream,
    writeHeaders: Boolean = true,
  ): Pair<AgeHeader, OutputStream> {
    if (recipients.isEmpty()) {
      throw NoRecipientsException("No recipients specified")
    }

    val fileKey = generateFileKey()
    val stanzas = mutableListOf<AgeStanza>()
    var labels = emptyList<String>()

    for (idx in 0 until recipients.size) {
      val recipient = requireNotNull(recipients[idx])
      val (s, l) = wrapWithLabels(recipient, fileKey)
      val sorted = l.sorted()
      stanzas.addAll(s)
      if (idx == 0) {
        labels = sorted
        continue
      }
      if (labels != sorted) {
        throw InvalidScryptRecipientException("incompatible scrypt recipients")
      }
    }

    // TODO: Check if we need a deep copy of stanzas here
    val ageHeader = AgeHeader.withMac(stanzas, fileKey)

    val nonce = ByteArray(STREAM_NONCE_SIZE)
    SecureRandom().nextBytes(nonce)

    if (writeHeaders) {
      val writer = dst.bufferedWriter()
      ageHeader.write(writer)
      // Need to flush the wrapping stream before writing again to the underlying stream
      writer.flush()
    }

    dst.write(nonce)

    val streamKey = Primitives.streamKey(fileKey, nonce)

    return Pair(ageHeader, EncryptOutputStream(streamKey, dst))
  }

  private fun wrapWithLabels(
    recipient: Recipient,
    fileKey: ByteArray,
  ): Pair<List<AgeStanza>, List<String>> {
    if (recipient is RecipientWithLabels) {
      return recipient.wrapWithLabels(fileKey)
    }
    return Pair(recipient.wrap(fileKey), emptyList())
  }

  private fun generateFileKey(): ByteArray {
    val fileKey = ByteArray(FILE_KEY_SIZE)
    SecureRandom().nextBytes(fileKey)
    return fileKey
  }

  // Unwraps the file key from [header] with the first matching identity and authenticates the
  // header against it. Shared by every decryption entry point so they cannot drift apart.
  private fun resolveFileKey(identities: List<Identity>, header: AgeHeader): ByteArray {
    if (identities.isEmpty()) throw NoIdentitiesException("no identities specified")

    header.recipients.forEach { stanza ->
      if (stanza.type == ScryptRecipient.SCRYPT_STANZA_TYPE && header.recipients.size != 1)
        throw ScryptIdentityException("an scrypt identity must be the only one")
    }

    val exceptions = mutableListOf<Exception>()

    for (identity in identities) {
      val fileKey =
        try {
          identity.unwrap(header.recipients)
        } catch (err: Exception) {
          exceptions.add(err)
          continue
        }

      if (header.mac.size != HMAC_SIZE) throw InvalidHMACHeaderException("invalid header mac")

      val calculatedMac = Primitives.headerMAC(fileKey, header)

      if (!MessageDigest.isEqual(header.mac, calculatedMac))
        throw IncorrectHMACException("bad header MAC")

      return fileKey
    }

    throw exceptions.reduce { acc, exception -> acc.apply { addSuppressed(exception) } }
  }

  // Wraps [srcStream] in an ArmorInputStream when it starts with an armor header, so that callers
  // always read binary age data.
  private fun decodeArmor(srcStream: InputStream): InputStream {
    val markSupportedStream =
      if (srcStream.markSupported()) srcStream else BufferedInputStream(srcStream)

    // Check if the InputStream contains whitespace + header
    val readLimit = ArmorInputStream.MAX_WHITESPACE + ArmorInputStream.HEADER.length
    markSupportedStream.mark(readLimit)

    val initialBytes = ByteArray(readLimit)
    val bytesRead = markSupportedStream.read(initialBytes, 0, readLimit)
    if (bytesRead == -1) {
      throw InvalidHMACHeaderException("stream was too short")
    }
    val initialString = String(initialBytes, 0, bytesRead)

    markSupportedStream.reset()

    return if (initialString.contains(ArmorInputStream.HEADER_START)) {
      ArmorInputStream(markSupportedStream)
    } else markSupportedStream
  }

  private fun decryptInternal(identities: List<Identity>, ageFile: AgeFile): InputStream {
    val fileKey = resolveFileKey(identities, ageFile.header)

    val nonce = ByteArray(STREAM_NONCE_SIZE)
    ageFile.body.copyInto(nonce, 0, 0, STREAM_NONCE_SIZE)

    val streamKey = Primitives.streamKey(fileKey, nonce)

    val bis = ByteArrayInputStream(ageFile.body)
    bis.skip(STREAM_NONCE_SIZE.toLong())

    return DecryptInputStream(streamKey, bis)
  }

  // Streaming counterpart of decryptInternal: parses the header off [src], then decrypts the
  // remaining live stream chunk-by-chunk into [dstStream] without holding the body in memory.
  private fun decryptStreamInternal(
    identities: List<Identity>,
    src: BufferedInputStream,
    dstStream: OutputStream,
  ) {
    val header = AgeHeader.parse(src)

    val fileKey = resolveFileKey(identities, header)

    val nonce = ByteArray(STREAM_NONCE_SIZE)
    var nonceOffset = 0
    while (nonceOffset < STREAM_NONCE_SIZE) {
      val read = src.read(nonce, nonceOffset, STREAM_NONCE_SIZE - nonceOffset)
      if (read == -1) throw InvalidNonceException("could not read payload nonce: stream truncated")
      nonceOffset += read
    }

    val streamKey = Primitives.streamKey(fileKey, nonce)

    DecryptInputStream(streamKey, src).use { decrypted ->
      dstStream.use { dst -> decrypted.copyTo(dst) }
    }
  }
}
