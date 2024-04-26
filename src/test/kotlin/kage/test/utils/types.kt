/**
 * Copyright 2022 The kage Authors. All rights reserved. Use of this source code is governed by
 * either an Apache 2.0 or MIT license at your discretion, that can be found in the LICENSE-APACHE
 * or LICENSE-MIT files respectively.
 */
package kage.test.utils

enum class Expect {
  Success,
  HMACFailure,
  HeaderFailure,
  ArmorFailure,
  PayloadFailure,
  NoMatch;

  companion object {
    fun fromString(value: String): Expect {
      return when (value) {
        "success" -> Success
        "HMAC failure" -> HMACFailure
        "header failure" -> HeaderFailure
        "armor failure" -> ArmorFailure
        "payload failure" -> PayloadFailure
        "no match" -> NoMatch
        else -> throw IllegalArgumentException("unknown expect value: $value")
      }
    }
  }
}

class PayloadHash(val bytes: ByteArray) {
  companion object {
    fun from(value: String): PayloadHash {
      check(value.length % 2 == 0) { "Must have an even length" }
      val hex = value.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
      check(hex.size == 32) { "Payload hash should be exactly 32 bytes" }
      return PayloadHash(hex)
    }
  }
}
