/**
 * Copyright 2022 The kage Authors. All rights reserved. Use of this source code is governed by
 * either an Apache 2.0 or MIT license at your discretion, that can be found in the LICENSE-APACHE
 * or LICENSE-MIT files respectively.
 */
package kage.crypto.stream

import com.google.common.truth.Truth.assertThat
import kage.crypto.stream.ChaCha20Poly1305.NONCE_LENGTH
import kage.errors.StreamException
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows

class StreamTest {
  @Test
  fun incNonce_incrementsCounterWithoutChangingLastByte() {
    val nonce = ByteArray(NONCE_LENGTH)
    nonce[NONCE_LENGTH - 1] = 7

    Stream.incNonce(nonce)

    assertThat(nonce[NONCE_LENGTH - 2]).isEqualTo(1.toByte())
    assertThat(nonce[NONCE_LENGTH - 1]).isEqualTo(7.toByte())
  }

  @Test
  fun incNonce_carriesAcrossTrailingCounterBytes() {
    val nonce = ByteArray(NONCE_LENGTH)
    nonce[NONCE_LENGTH - 3] = 4
    nonce[NONCE_LENGTH - 2] = 0xff.toByte()

    Stream.incNonce(nonce)

    assertThat(nonce[NONCE_LENGTH - 3]).isEqualTo(5.toByte())
    assertThat(nonce[NONCE_LENGTH - 2]).isEqualTo(0)
  }

  @Test
  fun incNonce_incrementsMostSignificantCounterByte() {
    val nonce = ByteArray(NONCE_LENGTH) { 0xff.toByte() }
    nonce[0] = 1

    Stream.incNonce(nonce)

    assertThat(nonce[0]).isEqualTo(2.toByte())
    assertThat(nonce.sliceArray(1 until NONCE_LENGTH - 1).asList())
      .containsExactlyElementsIn(List(NONCE_LENGTH - 2) { 0.toByte() })
  }

  @Test
  fun incNonce_throwsWhenCounterWraps() {
    val nonce = ByteArray(NONCE_LENGTH) { 0xff.toByte() }

    val error = assertThrows<StreamException> { Stream.incNonce(nonce) }

    assertThat(error).hasMessageThat().isEqualTo("stream: chunk counter wrapped around")
  }

  @Test
  fun nonceIsZero_checksEveryNonceByte() {
    assertThat(Stream.nonceIsZero(ByteArray(NONCE_LENGTH))).isTrue()
    assertThat(Stream.nonceIsZero(ByteArray(NONCE_LENGTH).also { it[0] = 1 })).isFalse()
  }

  @Test
  fun setLastChunkFlag_changesOnlyTheFinalByte() {
    val nonce = ByteArray(NONCE_LENGTH) { 3 }

    Stream.setLastChunkFlag(nonce)

    assertThat(nonce.take(NONCE_LENGTH - 1))
      .containsExactlyElementsIn(List(NONCE_LENGTH - 1) { 3.toByte() })
    assertThat(nonce.last()).isEqualTo(1.toByte())
  }
}
