package kage.format

import java.io.BufferedReader

public class AgeKey(header: AgeHeader, body: ByteArray) {

  public var header: AgeHeader = header
    private set

  public var body: ByteArray = body
    private set

  override fun equals(other: Any?): Boolean {
    if (other == null) return false
    if (other !is AgeKey) return false

    if (this === other) return true

    if (header != other.header) return false
    if (!body.contentEquals(other.body)) return false

    return true
  }

  override fun hashCode(): Int {
    var result = header.hashCode()
    result = 31 * result + body.contentHashCode()
    return result
  }

  internal companion object {
    internal const val VERSION_LINE = "age-encryption.org/v1"
    internal const val RECIPIENT_PREFIX = "->"
    internal const val FOOTER_PREFIX = "---"
    internal const val COLUMNS_PER_LINE = 64
    internal const val BYTES_PER_LINE = COLUMNS_PER_LINE / 4 * 3

    internal fun parse(reader: BufferedReader): AgeKey {
      val header = AgeHeader.parse(reader)
      TODO("We need to parse the body")
    }
  }
}
