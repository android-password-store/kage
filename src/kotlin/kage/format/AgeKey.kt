package kage.format

public data class AgeKey(val header: AgeHeader, val body: ByteArray) {
  internal companion object {
    internal const val VERSION_LINE = "age-encryption.org/v1"
    internal const val RECIPIENT_PREFIX = "->"
    internal const val FOOTER_PREFIX = "---"
    internal const val COLUMNS_PER_LINE = 64
    internal const val BYTES_PER_LINE = COLUMNS_PER_LINE / 4 * 3
  }
}
