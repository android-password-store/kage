/**
 * Copyright 2022 The kage Authors. All rights reserved. Use of this source code is governed by
 * either an Apache 2.0 or MIT license at your discretion, that can be found in the LICENSE-APACHE
 * or LICENSE-MIT files respectively.
 */
package kage.utils

import com.google.common.truth.Truth.assertThat
import kage.errors.InvalidBase64StringException
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertDoesNotThrow
import org.junit.jupiter.api.assertThrows

class ExtensionsTest {

  @Test
  fun testIsCanonicalBase6() {
    val canonicalString = "rF0/NwblUHHTpgQgRpe5CQ"
    val nonCanonicalString = "rF0/NwblUHHTpgQgRpe5CR"
    assertThat(canonicalString.isCanonicalBase64().first).isTrue()
    assertThat(canonicalString.isCanonicalBase64().second)
      .isEqualTo(byteArrayOf(-84, 93, 63, 55, 6, -27, 80, 113, -45, -90, 4, 32, 70, -105, -71, 9))
    assertThat(nonCanonicalString.isCanonicalBase64().first).isFalse()
    assertThat(nonCanonicalString.isCanonicalBase64().second)
      .isEqualTo(byteArrayOf(-84, 93, 63, 55, 6, -27, 80, 113, -45, -90, 4, 32, 70, -105, -71, 9))
  }

  @Test
  fun testDecodeBase64() {
    val canonicalString = "rF0/NwblUHHTpgQgRpe5CQ"
    val nonCanonicalString = "rF0/NwblUHHTpgQgRpe5CR"

    assertDoesNotThrow { canonicalString.decodeBase64() }
    assertThrows<InvalidBase64StringException> { nonCanonicalString.decodeBase64() }
  }
}
