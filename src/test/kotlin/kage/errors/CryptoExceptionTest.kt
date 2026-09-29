/**
 * Copyright 2022 The kage Authors. All rights reserved. Use of this source code is governed by
 * either an Apache 2.0 or MIT license at your discretion, that can be found in the LICENSE-APACHE
 * or LICENSE-MIT files respectively.
 */
package kage.errors

import com.google.common.truth.Truth.assertThat
import org.junit.jupiter.api.Test

class CryptoExceptionTest {
  @Test
  fun noRecipientsException_preservesMessageAndCause() {
    val cause = IllegalStateException("cause")

    val exception = NoRecipientsException("no recipients", cause)

    assertThat(exception.message).isEqualTo("no recipients")
    assertThat(exception.cause).isSameInstanceAs(cause)
  }

  @Test
  fun noRecipientsException_supportsDefaultArguments() {
    val exception = NoRecipientsException()

    assertThat(exception.message).isNull()
    assertThat(exception.cause).isNull()
  }

  @Test
  fun sshIdentityException_preservesMessageAndCause() {
    val cause = IllegalArgumentException("cause")

    val exception = SshIdentityException("ssh identity", cause)

    assertThat(exception.message).isEqualTo("ssh identity")
    assertThat(exception.cause).isSameInstanceAs(cause)
  }

  @Test
  fun sshIdentityException_supportsDefaultArguments() {
    val exception = SshIdentityException()

    assertThat(exception.message).isNull()
    assertThat(exception.cause).isNull()
  }
}
