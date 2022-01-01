package kage.utils

import java.io.Writer
import java.util.Base64

internal fun ByteArray.encodeBase64(): String {
  return Base64.getEncoder().withoutPadding().encodeToString(this)
}

internal fun String.decodeBase64(): ByteArray {
  return Base64.getDecoder().decode(this)
}

// Writer.newLine() uses System.lineSeparator(), we want to only use \n
internal fun Writer.writeNewLine() {
  write("\n")
}

internal fun Writer.writeSpace() {
  write(" ")
}
