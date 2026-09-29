/**
 * Copyright 2026 The kage Authors. All rights reserved. Use of this source code is governed by
 * either an Apache 2.0 or MIT license at your discretion, that can be found in the LICENSE-APACHE
 * or LICENSE-MIT files respectively.
 */
package kage.kage.crypto.ssh

import kage.crypto.ssh.OpenSshCipher
import kage.errors.UnsupportedSshKeyException
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows

class OpenSshCipherTest {
  @Test
  fun unknownCipherIsRejected() {
    assertThrows<UnsupportedSshKeyException> { OpenSshCipher.keyAndIvLength("aes128-unknown") }
  }
}
