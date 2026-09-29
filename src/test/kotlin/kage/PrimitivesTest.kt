/**
 * Copyright 2022 The kage Authors. All rights reserved. Use of this source code is governed by
 * either an Apache 2.0 or MIT license at your discretion, that can be found in the LICENSE-APACHE
 * or LICENSE-MIT files respectively.
 */
package kage

import com.google.common.truth.Truth.assertThat
import java.io.IOException
import kage.format.AgeHeader
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows

class PrimitivesTest {

  @Test
  fun headerMacSerializesHeaderWithoutMac() {
    val header = AgeHeader(emptyList(), byteArrayOf(1))

    val mac = Primitives.headerMAC(ByteArray(16), header)

    assertThat(mac).hasLength(32)
  }

  @Test
  fun headerMacClosesWriterWhenHeaderSerializationFails() {
    val recipients =
      object : AbstractList<kage.format.AgeStanza>() {
        override val size: Int = 1

        override fun get(index: Int): kage.format.AgeStanza =
          throw IOException("serialization failed")
      }

    assertThrows<IOException> {
      Primitives.headerMAC(ByteArray(16), AgeHeader(recipients, byteArrayOf(1)))
    }
  }

  @Test
  fun streamKeyDerivesPayloadKey() {
    val key = Primitives.streamKey(ByteArray(16), ByteArray(16))

    assertThat(key).hasLength(32)
  }
}
