/**
 * Copyright 2026 The kage Authors. All rights reserved. Use of this source code is governed by
 * either an Apache 2.0 or MIT license at your discretion, that can be found in the LICENSE-APACHE
 * or LICENSE-MIT files respectively.
 */
package kage.crypto.ssh

import com.google.common.truth.Truth.assertThat
import java.security.MessageDigest
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows

class Ed25519ConversionsTest {
  @Test
  fun publicKeyConversionRejectsWrongLengthAndInvalidPoints() {
    assertThrows<IllegalArgumentException> {
      Ed25519Conversions.publicKeyToCurve25519(ByteArray(31))
    }
    assertThrows<kage.errors.InvalidSshKeyException> {
      Ed25519Conversions.publicKeyToCurve25519(ByteArray(32))
    }
    // The Edwards identity (y = 1) is rejected as low-order by validatePublicKeyFull before the
    // explicit zero-denominator defense can be reached.
    assertThrows<kage.errors.InvalidSshKeyException> {
      Ed25519Conversions.publicKeyToCurve25519(byteArrayOf(1) + ByteArray(31))
    }
  }

  @Test
  fun seedConversionsRequire32Bytes() {
    assertThrows<IllegalArgumentException> {
      Ed25519Conversions.publicKeyFromPrivateSeed(ByteArray(31))
    }
    assertThrows<IllegalArgumentException> {
      Ed25519Conversions.privateSeedToCurve25519(ByteArray(31))
    }
  }

  @Test
  fun conversionsProduceExpectedFixedWidthValues() {
    val seed = ByteArray(32) { it.toByte() }
    val publicKey = Ed25519Conversions.publicKeyFromPrivateSeed(seed)

    assertThat(publicKey).hasLength(32)
    assertThat(Ed25519Conversions.publicKeyToCurve25519(publicKey)).hasLength(32)
    assertThat(Ed25519Conversions.privateSeedToCurve25519(seed))
      .isEqualTo(MessageDigest.getInstance("SHA-512").digest(seed).copyOfRange(0, 32))
  }
}
