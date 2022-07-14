/**
 * Copyright 2021 The kage Authors. All rights reserved. Use of this source code is governed by
 * either an Apache 2.0 or MIT license at your discretion, that can be found in the LICENSE-APACHE
 * or LICENSE-MIT files respectively.
 */
package kage.crypto.x25519

import org.bouncycastle.math.ec.rfc7748.X25519

public object X25519 {
  public val BASEPOINT: ByteArray =
    byteArrayOf(
      9,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0
    )

  public const val POINT_SIZE_: Int = X25519.POINT_SIZE

  public fun scalarMult(input: ByteArray, r: ByteArray): ByteArray {
    val out = ByteArray(input.size)

    X25519.scalarMult(input, 0, r, 0, out, 0)

    return out
  }
}
