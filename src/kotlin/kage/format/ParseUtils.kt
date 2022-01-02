/**
 * Copyright 2021 The kage Authors. All rights reserved. Use of this source code is governed by
 * either an Apache 2.0 or MIT license at your discretion, that can be found in the LICENSE-APACHE
 * or LICENSE-MIT files respectively.
 */
package kage.format

import kage.errors.InvalidArbitraryStringException

internal object ParseUtils {
  /*
   * Splits a line over ' ' and returns a pair with the line prefix and the arguments
   */
  @JvmStatic
  internal fun splitArgs(line: String): Pair<String, List<String>> {
    // Split recipient line over " "
    val parts = line.split(" ")
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
    if (string.isEmpty())
      throw InvalidArbitraryStringException("Arbitrary string should not be empty")
    string.forEach { char -> if (char.code < 33 || char.code > 126) return false }
    return true
  }
}
