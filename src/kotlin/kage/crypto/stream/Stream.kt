/**
 * Copyright 2022 The kage Authors. All rights reserved. Use of this source code is governed by
 * either an Apache 2.0 or MIT license at your discretion, that can be found in the LICENSE-APACHE
 * or LICENSE-MIT files respectively.
 */
package kage.crypto.stream

import kage.crypto.stream.ChaCha20Poly1305.NONCE_LENGTH
import kage.errors.StreamException

internal object Stream {
  fun incNonce(nonce: ByteArray) {
    for (i in nonce.size - 2 downTo 0) {
      nonce[i]++

      if (nonce[i] != 0.toByte()) break
      else if (i == 0) throw StreamException("stream: chunk counter wrapped around")
    }
  }

  fun nonceIsZero(nonce: ByteArray): Boolean = nonce.contentEquals(ByteArray(NONCE_LENGTH))

  fun setLastChunkFlag(nonce: ByteArray) {
    nonce[nonce.size - 1] = 0x01
  }
}
