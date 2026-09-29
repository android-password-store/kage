/**
 * Copyright 2022 The kage Authors. All rights reserved. Use of this source code is governed by
 * either an Apache 2.0 or MIT license at your discretion, that can be found in the LICENSE-APACHE
 * or LICENSE-MIT files respectively.
 */
package kage.crypto.x25519

import com.github.michaelbull.result.getOrThrow
import com.google.common.truth.Truth.assertThat
import kage.errors.X25519IdentityException
import kage.format.AgeKeyFile
import kage.format.Bech32
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows

class X25519IdentityTest {
  @Test
  fun decodeRejectsPrivateKeyWithIncorrectLength() {
    val encoded = Bech32.encode(AgeKeyFile.AGE_SECRET_KEY_PREFIX, ByteArray(31)).getOrThrow()

    val exception = assertThrows<X25519IdentityException> { X25519Identity.decode(encoded) }

    assertThat(exception).hasMessageThat().contains("Invalid X25519 private key size")
  }

  @Test
  fun decodeRejectsIncorrectHumanReadablePart() {
    val encoded = Bech32.encode("notage", ByteArray(32)).getOrThrow()

    val exception = assertThrows<X25519IdentityException> { X25519Identity.decode(encoded) }

    assertThat(exception).hasMessageThat().contains("Invalid human readable part")
  }
}
