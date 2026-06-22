/**
 * Copyright 2022 The kage Authors. All rights reserved. Use of this source code is governed by
 * either an Apache 2.0 or MIT license at your discretion, that can be found in the LICENSE-APACHE
 * or LICENSE-MIT files respectively.
 */
package kage.crypto.ssh

import java.math.BigInteger
import java.security.MessageDigest
import kage.errors.InvalidSshKeyException
import org.bouncycastle.math.ec.rfc8032.Ed25519

/**
 * Birational maps between the Ed25519 (Edwards) and Curve25519 (Montgomery) forms, matching how age
 * derives X25519 keys from SSH Ed25519 keys. age does this with
 * `edwards25519.Point.BytesMontgomery` for public keys and `SHA-512(seed)` for private keys; we
 * reproduce both so wrapping/unwrapping interoperates with the reference implementation.
 */
internal object Ed25519Conversions {
  // The field prime for Curve25519/Ed25519: 2^255 - 19.
  private val P: BigInteger = BigInteger.ONE.shiftLeft(255).subtract(BigInteger.valueOf(19))

  /**
   * Maps an Ed25519 public key (a 32-byte little-endian encoded Edwards point) to its Curve25519
   * Montgomery u-coordinate, encoded little-endian. RFC 7748 section 4.1: u = (1 + y) / (1 - y).
   */
  fun publicKeyToCurve25519(ed25519PublicKey: ByteArray): ByteArray {
    require(ed25519PublicKey.size == 32) { "ed25519 public key must be 32 bytes" }
    // Reject off-curve, non-canonical, and low-order keys (e.g. all-zero); they have no usable
    // Montgomery form and would yield a degenerate X25519 secret.
    if (!Ed25519.validatePublicKeyFull(ed25519PublicKey, 0))
      throw InvalidSshKeyException("invalid ssh-ed25519 public key")
    val le = ed25519PublicKey.copyOf()
    le[31] = (le[31].toInt() and 0x7f).toByte() // drop the encoded x sign bit, leaving y
    val y = leToBigInteger(le)
    val num = BigInteger.ONE.add(y).mod(P)
    val den = BigInteger.ONE.subtract(y).mod(P)
    // den == 0 (i.e. y == 1) is the Edwards identity point, which has no Montgomery u-coordinate;
    // reject it rather than letting modInverse throw a bare ArithmeticException.
    if (den.signum() == 0) throw InvalidSshKeyException("invalid ssh-ed25519 public key")
    val u = num.multiply(den.modInverse(P)).mod(P)
    return bigIntegerToLe(u)
  }

  /**
   * Derives the Curve25519 scalar from an Ed25519 private seed: the low 32 bytes of SHA-512(seed).
   * Clamping is left to the X25519 scalar multiplication, exactly as age relies on
   * curve25519.X25519.
   */
  fun privateSeedToCurve25519(seed: ByteArray): ByteArray {
    require(seed.size == 32) { "ed25519 seed must be 32 bytes" }
    val h = MessageDigest.getInstance("SHA-512").digest(seed)
    return h.copyOfRange(0, 32)
  }

  private fun leToBigInteger(le: ByteArray): BigInteger {
    // Reverse to big-endian and prepend a zero byte so the value is always interpreted as positive.
    val be = ByteArray(le.size + 1)
    for (i in le.indices) be[le.size - i] = le[i]
    return BigInteger(be)
  }

  private fun bigIntegerToLe(value: BigInteger): ByteArray {
    val out = ByteArray(32)
    var v = value
    val mask = BigInteger.valueOf(0xff)
    for (i in 0 until 32) {
      out[i] = v.and(mask).toInt().toByte()
      v = v.shiftRight(8)
    }
    return out
  }
}
