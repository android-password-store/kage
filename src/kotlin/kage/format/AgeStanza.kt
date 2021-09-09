package kage.format

import java.io.BufferedReader
import java.util.Base64
import kage.format.AgeKey.Companion.BYTES_PER_LINE
import kage.format.AgeKey.Companion.FOOTER_PREFIX
import kage.format.AgeKey.Companion.RECIPIENT_PREFIX
import kage.format.ParseUtils.isValidArbitraryString
import kage.format.ParseUtils.splitArgs

public data class AgeStanza(val type: String, val args: List<String>, val body: ByteArray) {

  override fun equals(other: Any?): Boolean {
    if (other == null) return false
    if (other !is AgeStanza) return false

    if (this === other) return true

    if (type != other.type) return false
    if (args != other.args) return false
    if (!body.contentEquals(other.body)) return false

    return true
  }

  override fun hashCode(): Int {
    var result = type.hashCode()
    result = 31 * result + args.hashCode()
    result = 31 * result + body.contentHashCode()
    return result
  }

  internal companion object {
    @JvmStatic
    internal fun parse(reader: BufferedReader): AgeStanza {
      // The first line should be a recipient line with at least one argument
      val recipientLine = reader.readLine()
      val (type, args) = parseRecipientLine(recipientLine)

      // Pass the reader object to parse the body of the recipient
      val body = parseBodyLines(reader)

      return AgeStanza(type, args, body)
    }

    /* Age Spec:
     * Each recipient stanza starts with a line beginning with -> and its type name,
     * followed by zero or more SP-separated arguments. The type name and the arguments
     * are arbitrary strings. Unknown recipient types are ignored.
     *
     * Example:
     * ->(RECIPIENT_PREFIX) X25519(TYPE_NAME) 8hWaIUmk67IuRZ41zMk2V9f/w3f5qUnXLL7MGPA+zE8(ARGUMENTS)
     */
    @JvmStatic
    internal fun parseRecipientLine(recipientLine: String): Pair<String, List<String>> {
      val (prefix, args) = splitArgs(recipientLine)

      if (prefix != RECIPIENT_PREFIX)
        throw InvalidRecipientException("Recipient line does not start with '->': $recipientLine")
      if (args.isEmpty())
        throw InvalidRecipientException("Recipient line does not contain any type: $recipientLine")

      args.forEach { arg ->
        if (!isValidArbitraryString(arg))
          throw InvalidArbitraryStringException("Argument: '$arg' is not a valid arbitrary string")
      }

      // First element is the type name
      val type = args.first()
      // Second is the list of stanza arguments
      val stanzaArgs = args.drop(1)

      return Pair(type, stanzaArgs)
    }

    /* Age Spec:
     * ... The rest of the recipient stanza is a body of canonical base64 from RFC 4648 without padding wrapped at
     * exactly 64 columns.
     */
    @JvmStatic
    internal fun parseBodyLines(reader: BufferedReader): ByteArray {
      // Create a mutable byteList which will hold all the bytes while we're parsing the body
      val byteList = mutableListOf<Byte>()
      val charArray = CharArray(3)
      var stopParsing = false

      do {
        // Add a mark to be able to reset the reader after reading the first 3 characters of the
        // line
        reader.mark(3)
        reader.read(charArray)
        val incompleteString = charArray.concatToString()

        // Reset the reader back to the start of the line
        reader.reset()

        // Always check using startsWith instead of contains otherwise "\n->" will be a false
        // positive
        if (incompleteString.startsWith(RECIPIENT_PREFIX)) {
          throw IncompleteRecipientException(
            "Encountered a new stanza while parsing the current one : ${reader.readLine()}"
          )
        }
        if (incompleteString.startsWith(FOOTER_PREFIX)) {
          throw IncompleteRecipientException(
            "Encountered the footer while parsing the current stanza: ${reader.readLine()}"
          )
        }

        val line =
          reader.readLine()
            ?: throw InvalidRecipientException(
              "Line is null, did you forget an extra newline after a full length body chunk?"
            )

        val bytes = Base64.getDecoder().decode(line)
        if (bytes.size > BYTES_PER_LINE)
          throw InvalidRecipientException("Body line is too long: $line")

        // Add the bytes to the byteList
        byteList.addAll(bytes.asList())

        if (bytes.size < BYTES_PER_LINE) stopParsing = true
      } while (!stopParsing)

      return byteList.toByteArray()
    }
  }
}
