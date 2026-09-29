/**
 * Copyright 2026 The kage Authors. All rights reserved. Use of this source code is governed by
 * either an Apache 2.0 or MIT license at your discretion, that can be found in the LICENSE-APACHE
 * or LICENSE-MIT files respectively.
 */
package kage.crypto.mlkem

import com.google.common.truth.Truth.assertThat
import kage.errors.InvalidRecipientException
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows

class MlKem768X25519Test {

  @Test
  fun testEncapsulateRejectsWrongPublicKeySize() {
    val exception =
      assertThrows<InvalidRecipientException> { MlKem768X25519.encapsulate(ByteArray(1)) }

    assertThat(exception.message).contains("Invalid key size")
  }
}
