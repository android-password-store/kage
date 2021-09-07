package kage.format

import java.io.BufferedReader
import java.util.Base64
import kage.format.AgeKey.Companion.FOOTER_PREFIX
import kage.format.AgeKey.Companion.RECIPIENT_PREFIX
import kage.format.AgeKey.Companion.VERSION_LINE
import kage.format.ParseUtils.splitArgs

public data class AgeHeader(val recipients: List<AgeStanza>, val mac: ByteArray) {

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

    internal fun parseVersion(reader: BufferedReader) {
      val versionLine = reader.readLine()
      parseVersionLine(versionLine)
    }

    internal fun parseVersionLine(versionLine: String) {
      if (versionLine != VERSION_LINE)
        throw ParseException("Version line is not correct: $versionLine")
    }

    internal fun parseRecipients(reader: BufferedReader): List<AgeStanza> {
      val recipientList = mutableListOf<AgeStanza>()
      val characterArray = CharArray(3)

      while (true) {
        // Add a mark to be able to reset the reader after reading the first 3 characters of the line
        reader.mark(3)
        if (reader.read(characterArray) == -1)
          throw ParseException("End of stream reached while reading recipients")

        val line = characterArray.concatToString()
        reader.reset()

        if (line.startsWith(RECIPIENT_PREFIX)) {
          recipientList.add(AgeStanza.parse(reader))
        } else if (line.startsWith(FOOTER_PREFIX)) {
          return recipientList
        } else {
          throw ParseException("Unexpected line found: ${reader.readLine()}")
        }
      }
    }

    internal fun parseFooter(reader: BufferedReader): ByteArray {
      val footerLine = reader.readLine()
      return parseFooterLine(footerLine)
    }

    internal fun parseFooterLine(footerLine: String): ByteArray {
      val (prefix, args) = splitArgs(footerLine)

      if (prefix != FOOTER_PREFIX)
        throw ParseException("Footer line does not start with '---': $footerLine")

      if (args.size != 1 || args.first().isEmpty()) throw ParseException("Footer line does not contain HMAC")

      return Base64.getDecoder().decode(args.first())
        ?: throw ParseException("Error parsing footer line")
    }
  }
}