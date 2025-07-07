/**
 * Copyright 2021-2022 The kage Authors. All rights reserved. Use of this source code is governed by
 * either an Apache 2.0 or MIT license at your discretion, that can be found in the LICENSE-APACHE
 * or LICENSE-MIT files respectively.
 */
package kage.format

import java.io.BufferedInputStream
import java.io.BufferedWriter
import kage.Primitives
import kage.errors.InvalidFooterException
import kage.errors.InvalidHMACException
import kage.errors.InvalidRecipientException
import kage.errors.InvalidVersionException
import kage.format.AgeFile.Companion.FOOTER_PREFIX
import kage.format.AgeFile.Companion.RECIPIENT_PREFIX
import kage.format.AgeFile.Companion.VERSION_LINE
import kage.format.ParseUtils.splitArgs
import kage.utils.decodeBase64
import kage.utils.encodeBase64
import kage.utils.readLine
import kage.utils.writeNewLine
import kage.utils.writeSpace

public class AgeHeader(public val recipients: List<AgeStanza>, public val mac: ByteArray) {

  internal fun write(writer: BufferedWriter) {
    if (mac.isEmpty()) throw InvalidHMACException("MAC must not be empty")
    writeWithoutMac(writer)
    writer.writeSpace()
    writer.write(mac.encodeBase64())
    writer.writeNewLine()
  }

  internal fun writeWithoutMac(writer: BufferedWriter) {
    writer.write(VERSION_LINE)
    writer.writeNewLine()
    for (recipient in recipients) {
      AgeStanza.write(writer, recipient)
    }
    writer.write(FOOTER_PREFIX)
  }

  override fun equals(other: Any?): Boolean {
    if (other == null) return false
    if (other !is AgeHeader) return false

    if (this === other) return true

    if (recipients != other.recipients) return false
    if (!mac.contentEquals(other.mac)) return false

    return true
  }

  override fun hashCode(): Int {
    var result = recipients.hashCode()
    result = 31 * result + mac.contentHashCode()
    return result
  }

  internal companion object {

    internal fun parse(reader: BufferedInputStream): AgeHeader {
      parseVersion(reader)
      val recipients = parseRecipients(reader)
      val mac = parseFooter(reader)

      return AgeHeader(recipients, mac)
    }

    internal fun parseVersion(reader: BufferedInputStream) {
      val versionLine = reader.readLine()
      parseVersionLine(versionLine)
    }

    /*
     * Age Spec:
     * The first line of the header is age-encryption.org/ followed by an arbitrary version string.
     */
    private fun parseVersionLine(versionLine: String?) {
      if (versionLine != VERSION_LINE)
        throw InvalidVersionException("Version line is not correct: $versionLine")
    }

    internal fun parseRecipients(reader: BufferedInputStream): List<AgeStanza> {
      val recipientList = mutableListOf<AgeStanza>()
      val buf = ByteArray(3)

      while (true) {
        // Add a mark to be able to reset the reader after reading the first 3 characters of the
        // line
        reader.mark(3)
        if (reader.read(buf) == -1)
          throw InvalidRecipientException("End of stream reached while reading recipients")

        val prefix = buf.decodeToString()
        reader.reset()

        if (prefix.startsWith(RECIPIENT_PREFIX)) {
          recipientList.add(AgeStanza.parse(reader))
        } else if (prefix.startsWith(FOOTER_PREFIX)) {
          return recipientList
        } else {
          throw InvalidRecipientException("Unexpected line found: ${reader.readLine()}")
        }
      }
    }

    internal fun parseFooter(reader: BufferedInputStream): ByteArray {
      val footerLine = reader.readLine() ?: throw InvalidFooterException("Footer line is empty")
      return parseFooterLine(footerLine)
    }

    /*
     * Age Spec:
     * The header ends with the following line
     * --- encode(HMAC[HKDF["", "header"](file key)](header))
     * where header is the whole header up to the --- mark included.
     */
    internal fun parseFooterLine(footerLine: String): ByteArray {
      val (prefix, args) = splitArgs(footerLine)

      if (prefix != FOOTER_PREFIX)
        throw InvalidFooterException("Footer line does not start with '---': $footerLine")

      // Age does not check if the mac is empty but the mac can never be empty, so let's keep the
      // `isEmpty` check
      if (args.size != 1 || args.first().isEmpty())
        throw InvalidFooterException("Footer line does not contain MAC")

      return args.first().decodeBase64()
    }

    internal fun withMac(stanzas: List<AgeStanza>, fileKey: ByteArray): AgeHeader {
      val ageHeaderWithoutMac = AgeHeader(stanzas, ByteArray(0))
      val mac = Primitives.headerMAC(fileKey, ageHeaderWithoutMac)

      return AgeHeader(stanzas, mac)
    }
  }
}
