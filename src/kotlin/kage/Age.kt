/**
 * Copyright 2021 The kage Authors. All rights reserved.
 * Use of this source code is governed by either an
 * Apache 2.0 or MIT license at your discretion, that can
 * be found in the LICENSE-APACHE or LICENSE-MIT files
 * respectively.
 */
package kage

import java.io.InputStream
import java.io.OutputStream
import java.security.SecureRandom
import kage.crypto.scrypt.ScryptRecipient
import kage.format.AgeHeader

public object Age {
  private const val FILE_KEY_SIZE = 16
  private const val STREAM_NONCE_SIZE = 16

  @JvmStatic
  public fun encrypt(
    recipients: List<Recipient>,
    inputStream: InputStream,
    outputStream: OutputStream,
    generateArmor: Boolean
  ) {
    TODO("Not yet implemented")
  }

  private fun encryptInternal(recipients: List<Recipient>, outputStream: OutputStream) {
    if (recipients.isEmpty()) {
      throw IllegalArgumentException("No recipients specified")
    }

    // From the age docs:
    // As a best effort, prevent an API user from generating a file that the
    // ScryptIdentity will refuse to decrypt. This check can't unfortunately be
    // implemented as part of the Recipient interface, so it lives as a special
    // case in Encrypt.
    // https://github.com/FiloSottile/age/blob/ab3707c085f2c1fdfd767a2ed718423e3925f4c4/age.go#L114-L122
    recipients.forEach { recipient ->
      if (recipient is ScryptRecipient && recipients.size != 1) {
        throw IllegalArgumentException("Only one scrypt recipient is supported")
      }
    }

    val fileKey = ByteArray(FILE_KEY_SIZE)
    SecureRandom().nextBytes(fileKey)

    val stanzas = recipients.flatMap { recipient -> recipient.wrap(fileKey) }
    val ageHeaderWithoutMac = AgeHeader(stanzas, ByteArray(0))
    val mac = Primitives.headerMAC(fileKey, ageHeaderWithoutMac)

    // TODO: Check if we need a deep copy of stanzas here
    val ageHeader = AgeHeader(stanzas, mac)

    val nonce = ByteArray(STREAM_NONCE_SIZE)
    SecureRandom().nextBytes(nonce)

    TODO("Add Stream reader and writer")
  }
}
