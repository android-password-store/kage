/**
 * Copyright 2021 The kage Authors. All rights reserved.
 * Use of this source code is governed by either an
 * Apache 2.0 or MIT license at your discretion, that can
 * be found in the LICENSE-APACHE or LICENSE-MIT files
 * respectively.
 */
package kage.format

import java.io.BufferedReader
import java.io.BufferedWriter
import java.util.Base64
import kage.format.AgeKey.Companion.FOOTER_PREFIX
import kage.format.AgeKey.Companion.RECIPIENT_PREFIX
import kage.format.AgeKey.Companion.VERSION_LINE
import kage.format.ParseUtils.splitArgs
import kage.utils.encodeBase64
import kage.utils.writeNewLine
import kage.utils.writeSpace

public class AgeHeader(public val recipients: List<AgeStanza>, public val mac: ByteArray) {

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

    internal fun parse(reader: BufferedReader): AgeHeader {
      parseVersion(reader)
      val recipients = parseRecipients(reader)
      val mac = parseFooter(reader)

      return AgeHeader(recipients, mac)
    }

    internal fun write(writer: BufferedWriter, header: AgeHeader) {
      if (header.mac.isEmpty()) throw IllegalArgumentException("MAC must not be empty")
      writeWithoutMac(writer, header)
      writer.writeSpace()
      writer.write(header.mac.encodeBase64())
      writer.writeNewLine()
    }

    internal fun writeWithoutMac(writer: BufferedWriter, header: AgeHeader) {
      writer.write(VERSION_LINE)
      writer.writeNewLine()
      for (recipient in header.recipients) {
        AgeStanza.write(writer, recipient)
      }
      writer.write(FOOTER_PREFIX)
    }

    internal fun parseVersion(reader: BufferedReader) {
      val versionLine = reader.readLine()
      parseVersionLine(versionLine)
    }

    /*
     * Age Spec:
     * The first line of the header is age-encryption.org/ followed by an arbitrary version string.
     */
    internal fun parseVersionLine(versionLine: String) {
      if (versionLine != VERSION_LINE)
        throw InvalidVersionException("Version line is not correct: $versionLine")
    }

    internal fun parseRecipients(reader: BufferedReader): List<AgeStanza> {
      val recipientList = mutableListOf<AgeStanza>()
      val characterArray = CharArray(3)

      while (true) {
        // Add a mark to be able to reset the reader after reading the first 3 characters of the
        // line
        reader.mark(3)
        if (reader.read(characterArray) == -1)
          throw InvalidRecipientException("End of stream reached while reading recipients")

        val line = characterArray.concatToString()
        reader.reset()

        if (line.startsWith(RECIPIENT_PREFIX)) {
          recipientList.add(AgeStanza.parse(reader))
        } else if (line.startsWith(FOOTER_PREFIX)) {
          return recipientList
        } else {
          throw InvalidRecipientException("Unexpected line found: ${reader.readLine()}")
        }
      }
    }

    internal fun parseFooter(reader: BufferedReader): ByteArray {
      val footerLine = reader.readLine()
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

      return Base64.getDecoder().decode(args.first())
        ?: throw InvalidFooterException("Error parsing footer line")
    }
  }
}
