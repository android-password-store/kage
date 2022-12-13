/**
 * Copyright 2022 The kage Authors. All rights reserved. Use of this source code is governed by
 * either an Apache 2.0 or MIT license at your discretion, that can be found in the LICENSE-APACHE
 * or LICENSE-MIT files respectively.
 */
package kage.kage.test.utils

import kage.Identity
import kage.crypto.scrypt.ScryptIdentity
import kage.crypto.x25519.X25519Identity
import kage.test.utils.Expect
import kage.test.utils.PayloadHash

class TestSuite
private constructor(
  val expect: Expect,
  val payloadHash: PayloadHash?,
  val identities: List<Identity>,
  val armored: Boolean,
  val testContent: ByteArray,
) {
  companion object {
    fun parse(contents: ByteArray): TestSuite {
      var expect: Expect? = null
      var payloadHash: PayloadHash? = null
      val identities = mutableListOf<Identity>()
      var armored = false

      var remaining = contents
      do {
        val (line, rest, found) = remaining.split('\n')
        if (!found) {
          error("invalid test file: no payload")
        }
        if (rest != null) remaining = rest
        if (line.isEmpty()) {
          break
        }
        val (key, value) = line.decodeToString().split(": ")
        when (key) {
          "expect" -> expect = Expect.fromString(value)
          "payload" -> payloadHash = PayloadHash.from(value)
          "identity" -> identities.add(X25519Identity.decode(value))
          "passphrase" -> identities.add(ScryptIdentity(value.encodeToByteArray()))
          "armored" -> armored = true
          "file key" -> {}
          "comment" -> {}
          else -> error("invalid test file: unknown header key: $key")
        }
      } while (true)

      check(expect != null) { "invalid test file: no 'expect' header found" }
      check((expect != Expect.Success || expect != Expect.PayloadFailure) || payloadHash != null) {
        // This check verifies that the payload is present except when expectation is either
        // Success or PayloadFailure
        "invalid test file: no 'payload' header found"
      }

      return TestSuite(expect, payloadHash, identities, armored, remaining)
    }
  }
}
