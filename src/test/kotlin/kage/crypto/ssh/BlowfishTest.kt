/**
 * Copyright 2022 The kage Authors. All rights reserved. Use of this source code is governed by
 * either an Apache 2.0 or MIT license at your discretion, that can be found in the LICENSE-APACHE
 * or LICENSE-MIT files respectively.
 */
package kage.kage.crypto.ssh

import com.google.common.truth.Truth.assertThat
import kage.crypto.ssh.Blowfish
import org.junit.jupiter.api.Test

class BlowfishTest {
  // The self-test vector from OpenBSD's lib/libc/crypt/blowfish.c.
  @Test
  fun encipher_matchesOpenBsdSelfTestVector() {
    val blowfish = Blowfish()
    blowfish.expand0State("abcdefghijklmnopqrstuvwxyz".toByteArray(Charsets.US_ASCII))

    val block = intArrayOf(0x424c4f57.toInt(), 0x46495348.toInt())
    blowfish.encipher(block)

    assertThat(block[0]).isEqualTo(0x324ed0fe.toInt())
    assertThat(block[1]).isEqualTo(0xf413a203.toInt())
  }
}
