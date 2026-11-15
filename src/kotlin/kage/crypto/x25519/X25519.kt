/**
 * Copyright 2022 The kage Authors. All rights reserved. Use of this source code is governed by
 * either an Apache 2.0 or MIT license at your discretion, that can be found in the LICENSE-APACHE
 * or LICENSE-MIT files respectively.
 */
package kage.crypto.x25519

import kage.errors.X25519LowOrderPointException
import org.bouncycastle.math.ec.rfc7748.X25519

/** Runs X25519 scalar multiplication for public and private keys. */
public object X25519 {

  /**
   * Multiplies the X25519 scalar [input] by the point [r].
   *
   * @param input 32-byte scalar
   * @param r 32-byte point
   * @return 32-byte shared point
   * @throws X25519LowOrderPointException if [r] is a low-order point
   */
  public fun scalarMult(input: ByteArray, r: ByteArray): ByteArray {
    val out = ByteArray(input.size)

    if (!X25519.calculateAgreement(input, 0, r, 0, out, 0))
      throw X25519LowOrderPointException("Low order point")

    return out
  }

  /**
   * Multiplies the X25519 scalar [input] by the standard base point.
   *
   * @param input 32-byte scalar
   * @return 32-byte public point
   */
  public fun scalarMultBase(input: ByteArray): ByteArray {
    val out = ByteArray(input.size)

    X25519.scalarMultBase(input, 0, out, 0)

    return out
  }
}
