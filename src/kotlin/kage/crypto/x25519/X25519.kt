/**
 * Copyright 2022 The kage Authors. All rights reserved. Use of this source code is governed by
 * either an Apache 2.0 or MIT license at your discretion, that can be found in the LICENSE-APACHE
 * or LICENSE-MIT files respectively.
 */
package kage.crypto.x25519

import kage.errors.X25519LowOrderPointException
import org.bouncycastle.math.ec.rfc7748.X25519

public object X25519 {

  public fun scalarMult(input: ByteArray, r: ByteArray): ByteArray {
    val out = ByteArray(input.size)

    if (!X25519.calculateAgreement(input, 0, r, 0, out, 0))
      throw X25519LowOrderPointException("Low order point")

    X25519.scalarMult(input, 0, r, 0, out, 0)
    return out
  }

  public fun scalarMultBase(input: ByteArray): ByteArray {
    val out = ByteArray(input.size)

    X25519.scalarMultBase(input, 0, out, 0)

    return out
  }
}
