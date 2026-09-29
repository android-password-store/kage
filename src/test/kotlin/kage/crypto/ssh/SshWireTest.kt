/**
 * Copyright 2026 The kage Authors. All rights reserved. Use of this source code is governed by
 * either an Apache 2.0 or MIT license at your discretion, that can be found in the LICENSE-APACHE
 * or LICENSE-MIT files respectively.
 */
package kage.crypto.ssh

import com.google.common.truth.Truth.assertThat
import java.io.EOFException
import java.math.BigInteger
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows

class SshWireTest {
  @Test
  fun readRawRejectsNegativeAndTruncatedLengths() {
    assertThrows<EOFException> { SshWireReader(byteArrayOf(1)).readRaw(-1) }
    assertThrows<EOFException> { SshWireReader(byteArrayOf(1)).readRaw(2) }
  }

  @Test
  fun readRawAndUInt32DecodeNetworkOrder() {
    val reader = SshWireReader(byteArrayOf(0x12, 0x34, 0x56, 0x78))

    assertThat(reader.readUInt32()).isEqualTo(0x12345678L)
    assertThat(reader.remaining()).isEqualTo(0)
  }

  @Test
  fun readStringRejectsLengthsLargerThanInt() {
    val tooLarge = byteArrayOf(0x80.toByte(), 0, 0, 0)

    assertThrows<EOFException> { SshWireReader(tooLarge).readString() }
  }

  @Test
  fun readMpintHandlesZeroAndSignedValues() {
    assertThat(SshWireReader(byteArrayOf(0, 0, 0, 0)).readMpint()).isEqualTo(BigInteger.ZERO)
    assertThat(SshWireReader(byteArrayOf(0, 0, 0, 1, 0xff.toByte())).readMpint())
      .isEqualTo(BigInteger.valueOf(-1))
  }
}
