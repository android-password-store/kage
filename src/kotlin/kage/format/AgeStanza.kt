package kage.format

import java.io.BufferedReader
import java.util.*

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
    private const val RECIPIENT_PREFIX = "->"
    private const val COLUMNS_PER_LINE = 64
    private const val BYTES_PER_LINE = COLUMNS_PER_LINE / 4 * 3

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
        throw ParseException("Recipient line does not start with '->': $recipientLine")
      if (args.isEmpty())
        throw ParseException("Recipient line does not contain any type: $recipientLine")

      args.forEach { arg ->
        if (!isValidArbitraryString(arg))
          throw ParseException("Argument: '$arg' is not a valid arbitrary string")
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
      var stopParsing = false
      do {
        val line =
          reader.readLine()
            ?: throw ParseException(
              "Line is null, did you forget an extra newline after a full length body chunk?"
            )
        val bytes = Base64.getDecoder().decode(line)
        if (bytes.size > BYTES_PER_LINE) throw ParseException("Body line is too long: $line")

        // Add the bytes to the byteList
        byteList.addAll(bytes.asList())

        if (bytes.size < BYTES_PER_LINE) stopParsing = true
      } while (!stopParsing)

      return byteList.toByteArray()
    }

    /*
     * Splits a line over ' ' and returns a pair with the line prefix and the arguments
     */
    @JvmStatic
    internal fun splitArgs(recipientLine: String): Pair<String, List<String>> {
      // Split recipient line over " "
      val parts = recipientLine.split(" ")
      // Drop '->' (RECIPIENT_PREFIX) from recipient line and return it along with the remaining
      // arguments
      return Pair(parts.first(), parts.drop(1))
    }

    /*
     * Age Spec:
     * ... an arbitrary string is a sequence of ASCII characters with values 33 to 126.
     */
    @JvmStatic
    internal fun isValidArbitraryString(string: String): Boolean {
      if (string.isEmpty()) throw ParseException("Arbitrary string should not be empty")
      string.forEach { char -> if (char.code < 33 || char.code > 126) return false }
      return true
    }
  }
}
