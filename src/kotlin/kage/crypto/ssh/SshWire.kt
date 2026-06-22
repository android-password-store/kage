/**
 * Copyright 2022 The kage Authors. All rights reserved. Use of this source code is governed by
 * either an Apache 2.0 or MIT license at your discretion, that can be found in the LICENSE-APACHE
 * or LICENSE-MIT files respectively.
 */
package kage.crypto.ssh

import java.io.EOFException
import java.math.BigInteger
import java.security.MessageDigest
import kage.utils.encodeBase64
import org.bouncycastle.crypto.digests.SHA256Digest
import org.bouncycastle.crypto.generators.HKDFBytesGenerator
import org.bouncycastle.crypto.params.HKDFParameters

/**
 * Minimal reader for the SSH wire encoding (RFC 4251 section 5): fixed-width [readRaw], 32-bit
 * lengths ([readUInt32]), length-prefixed byte strings ([readString]) and multiple-precision
 * integers ([readMpint]). Only what is needed to parse OpenSSH public and private keys.
 */
internal class SshWireReader(private val buf: ByteArray) {
  private var pos = 0

  fun readRaw(n: Int): ByteArray {
    if (n < 0 || pos + n > buf.size) throw EOFException("ssh wire: truncated bytes")
    val out = buf.copyOfRange(pos, pos + n)
    pos += n
    return out
  }

  fun readUInt32(): Long {
    val b = readRaw(4)
    return ((b[0].toLong() and 0xff) shl 24) or
      ((b[1].toLong() and 0xff) shl 16) or
      ((b[2].toLong() and 0xff) shl 8) or
      (b[3].toLong() and 0xff)
  }

  fun readString(): ByteArray {
    val len = readUInt32()
    if (len > Int.MAX_VALUE) throw EOFException("ssh wire: string too long")
    return readRaw(len.toInt())
  }

  /** Reads an mpint: a length-prefixed, signed, big-endian two's-complement integer. */
  fun readMpint(): BigInteger {
    val b = readString()
    return if (b.isEmpty()) BigInteger.ZERO else BigInteger(b)
  }

  fun remaining(): Int = buf.size - pos
}

/**
 * The age "SSH fingerprint": the first 4 bytes of the SHA-256 of the SSH wire encoding of the
 * public key, base64-encoded (raw, unpadded). Used as the recipient stanza tag so an identity can
 * tell whether a stanza was wrapped to its key.
 */
internal fun sshFingerprint(sshKeyBlob: ByteArray): String {
  val digest = MessageDigest.getInstance("SHA-256").digest(sshKeyBlob)
  return digest.copyOfRange(0, 4).encodeBase64()
}

/**
 * HKDF-SHA256 (RFC 5869) extract-and-expand. Uses BouncyCastle rather than the at.favre HKDF used
 * elsewhere because age's SSH key derivation runs an extract step with empty input keying material
 * (the per-key tweak), which the favre implementation rejects.
 */
internal fun hkdfSha256(salt: ByteArray, ikm: ByteArray, info: ByteArray, length: Int): ByteArray {
  val hkdf = HKDFBytesGenerator(SHA256Digest())
  hkdf.init(HKDFParameters(ikm, salt, info))
  val out = ByteArray(length)
  hkdf.generateBytes(out, 0, length)
  return out
}
