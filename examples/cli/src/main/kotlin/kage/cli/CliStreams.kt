/**
 * Copyright 2026 The kage Authors. All rights reserved. Use of this source code is governed by
 * either an Apache 2.0 or MIT license at your discretion, that can be found in the LICENSE-APACHE
 * or LICENSE-MIT files respectively.
 */
package kage.cli

import java.io.File
import java.io.InputStream
import java.io.OutputStream

internal object CliStreams {
  fun process(
    inputPath: String,
    outputPath: String?,
    operation: (InputStream, OutputStream) -> Unit,
  ) {
    val source = openInput(inputPath)
    val destination = openOutput(outputPath)
    try {
      operation(source, destination)
    } catch (failure: Exception) {
      runCatching { source.close() }
      runCatching { destination.close() }
      throw failure
    }
  }

  private fun openInput(path: String): InputStream =
    if (path == "-") System.`in` else File(path).inputStream()

  private fun openOutput(path: String?): OutputStream =
    if (path == null || path == "-") System.out else File(path).outputStream()
}

internal object PasswordPrompt {
  fun read(prompt: String): String {
    System.err.print(prompt)
    System.err.flush()

    val console = System.console()
    return if (console != null) String(console.readPassword()) else readLine() ?: ""
  }
}
