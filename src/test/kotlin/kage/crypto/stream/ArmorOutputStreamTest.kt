/**
 * Copyright 2023 The kage Authors. All rights reserved. Use of this source code is governed by
 * either an Apache 2.0 or MIT license at your discretion, that can be found in the LICENSE-APACHE
 * or LICENSE-MIT files respectively.
 */
package kage.crypto.stream

import com.google.common.truth.Truth.assertThat
import java.io.ByteArrayOutputStream
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows

class ArmorOutputStreamTest {
  @Test
  fun closeAfterRejectedWriteEmitsEmptyArmorLine() {
    val destination = ByteArrayOutputStream()
    val stream = ArmorOutputStream(destination)

    assertThrows<IndexOutOfBoundsException> { stream.write(byteArrayOf(), 0, 1) }

    stream.close()

    assertThat(destination.toString())
      .isEqualTo("${ArmorInputStream.HEADER}\n\n${ArmorInputStream.FOOTER}")
  }
}
