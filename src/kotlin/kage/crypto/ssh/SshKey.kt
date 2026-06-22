/**
 * Copyright 2022 The kage Authors. All rights reserved. Use of this source code is governed by
 * either an Apache 2.0 or MIT license at your discretion, that can be found in the LICENSE-APACHE
 * or LICENSE-MIT files respectively.
 */
package kage.crypto.ssh

import java.math.BigInteger
import java.util.Base64
import kage.Identity
import kage.Recipient
import kage.errors.InvalidSshKeyException
import kage.errors.UnsupportedSshKeyException
import org.bouncycastle.crypto.params.RSAKeyParameters
import org.bouncycastle.crypto.params.RSAPrivateCrtKeyParameters

/**
 * Parses SSH keys into kage [Recipient]s and [Identity]s.
 *
 * Public keys are read from a single `authorized_keys`-style line (`ssh-ed25519 AAAA... comment`).
 * Private keys are read from the unencrypted OpenSSH private key format (`-----BEGIN OPENSSH
 * PRIVATE KEY-----`). Passphrase-encrypted private keys are not yet supported.
 */
public object SshKey {
  private const val SSH_ED25519 = "ssh-ed25519"
  private const val SSH_RSA = "ssh-rsa"

  // The fixed OpenSSH private key magic: the ASCII "openssh-key-v1" followed by a NUL byte.
  private val AUTH_MAGIC = "openssh-key-v1".toByteArray(Charsets.US_ASCII).plus(0x00.toByte())

  /** Parses an `authorized_keys`-style public key line into a [Recipient]. */
  public fun parseRecipient(authorizedKey: String): Recipient {
    val (type, _) = parseAuthorizedKey(authorizedKey)
    return when (type) {
      SSH_ED25519 -> SshEd25519Recipient.parse(authorizedKey)
      SSH_RSA -> SshRsaRecipient.parse(authorizedKey)
      else -> throw UnsupportedSshKeyException("unsupported SSH key type: $type")
    }
  }

  /** Parses an unencrypted OpenSSH private key (PEM) into an [Identity]. */
  public fun parseIdentity(privateKey: String): Identity {
    val blob = decodeOpenSshPem(privateKey)
    // Normalize low-level wire errors (e.g. truncation) to InvalidSshKeyException, but let the
    // exceptions we raise on purpose pass through unchanged.
    return try {
      readIdentity(blob)
    } catch (e: InvalidSshKeyException) {
      throw e
    } catch (e: UnsupportedSshKeyException) {
      throw e
    } catch (e: Exception) {
      throw InvalidSshKeyException("malformed OpenSSH private key", e)
    }
  }

  private fun readIdentity(blob: ByteArray): Identity {
    val reader = SshWireReader(blob)

    val magic = reader.readRaw(AUTH_MAGIC.size)
    if (!magic.contentEquals(AUTH_MAGIC))
      throw InvalidSshKeyException("not an OpenSSH private key (bad magic)")

    val cipherName = String(reader.readString(), Charsets.US_ASCII)
    val kdfName = String(reader.readString(), Charsets.US_ASCII)
    reader.readString() // kdf options
    val numKeys = reader.readUInt32()
    if (numKeys != 1L) throw UnsupportedSshKeyException("multi-key OpenSSH files are not supported")

    val publicKeyBlob = reader.readString()
    val privateSection = reader.readString()

    if (cipherName != "none" || kdfName != "none")
      throw UnsupportedSshKeyException("passphrase-encrypted SSH keys are not supported")

    val priv = SshWireReader(privateSection)
    val check1 = priv.readUInt32()
    val check2 = priv.readUInt32()
    if (check1 != check2) throw InvalidSshKeyException("OpenSSH private key checksum mismatch")

    return when (val keyType = String(priv.readString(), Charsets.US_ASCII)) {
      SSH_ED25519 -> {
        val publicKey = priv.readString()
        if (publicKey.size != 32) throw InvalidSshKeyException("bad ed25519 public key length")
        val privateKeyBytes = priv.readString()
        if (privateKeyBytes.size != 64)
          throw InvalidSshKeyException("bad ed25519 private key length")
        // The private value is seed || public key; its embedded copy and the top-level blob must
        // both match the in-section public key, else identity and secret material disagree.
        if (!publicKey.contentEquals(privateKeyBytes.copyOfRange(32, 64)))
          throw InvalidSshKeyException("ed25519 public key does not match private key")
        if (!ed25519PublicKeyFromBlob(publicKeyBlob).contentEquals(publicKey))
          throw InvalidSshKeyException("ed25519 public key does not match private key")
        val seed = privateKeyBytes.copyOfRange(0, 32)
        SshEd25519Identity(publicKeyBlob, seed, publicKey)
      }
      SSH_RSA -> {
        // OpenSSH serializes the RSA private key as mpints in the order n, e, d, iqmp, p, q.
        val n = priv.readMpint()
        val e = priv.readMpint()
        val d = priv.readMpint()
        val iqmp = priv.readMpint()
        val p = priv.readMpint()
        val q = priv.readMpint()
        if (n.bitLength() < SshRsaRecipient.MIN_RSA_BITS)
          throw UnsupportedSshKeyException("RSA keys shorter than 2048 bits are not supported")
        // The top-level public blob must match the private parameters, else our published
        // fingerprint wouldn't belong to the key we decrypt with.
        val outer = rsaPublicKeyFromBlob(publicKeyBlob)
        if (outer.modulus != n || outer.exponent != e)
          throw InvalidSshKeyException("rsa public key does not match private key")
        val dp = d.mod(p.subtract(BigInteger.ONE))
        val dq = d.mod(q.subtract(BigInteger.ONE))
        SshRsaIdentity(publicKeyBlob, RSAPrivateCrtKeyParameters(n, e, d, p, q, dp, dq, iqmp))
      }
      else -> throw UnsupportedSshKeyException("unsupported SSH key type: $keyType")
    }
  }

  /**
   * Reads an `authorized_keys` line (`[options] <type> <base64-blob> [comment]`), returning (type,
   * key blob). The optional options field means the type isn't always first, so scan for the field
   * whose following blob's inner type string matches it.
   */
  internal fun parseAuthorizedKey(line: String): Pair<String, ByteArray> {
    val fields = line.trim().split(Regex("\\s+"))
    for (i in fields.indices) {
      val parsed = tryParseKeyTypeAt(fields, i)
      if (parsed != null) return parsed
    }
    throw InvalidSshKeyException("not an SSH public key line")
  }

  /**
   * Returns (type, blob) if [fields] at [index] names an SSH key type immediately followed by a
   * base64 blob whose inner type string matches it, otherwise null.
   */
  private fun tryParseKeyTypeAt(fields: List<String>, index: Int): Pair<String, ByteArray>? {
    if (index + 1 >= fields.size) return null
    val type = fields[index]
    val blob =
      try {
        Base64.getDecoder().decode(fields[index + 1])
      } catch (e: IllegalArgumentException) {
        return null
      }
    val inner =
      try {
        String(SshWireReader(blob).readString(), Charsets.US_ASCII)
      } catch (e: Exception) {
        return null
      }
    if (inner != type) return null
    return type to blob
  }

  /** Extracts the 32-byte Ed25519 public key from its SSH wire blob. */
  internal fun ed25519PublicKeyFromBlob(blob: ByteArray): ByteArray {
    val reader = SshWireReader(blob)
    reader.readString() // type
    val publicKey = reader.readString()
    if (publicKey.size != 32) throw InvalidSshKeyException("bad ed25519 public key length")
    return publicKey
  }

  /** Builds an RSA public key from its SSH wire blob (`string "ssh-rsa", mpint e, mpint n`). */
  internal fun rsaPublicKeyFromBlob(blob: ByteArray): RSAKeyParameters {
    val reader = SshWireReader(blob)
    reader.readString() // type
    val e = reader.readMpint()
    val n = reader.readMpint()
    if (n.bitLength() < SshRsaRecipient.MIN_RSA_BITS)
      throw UnsupportedSshKeyException("RSA keys shorter than 2048 bits are not supported")
    return RSAKeyParameters(false, n, e)
  }

  private fun decodeOpenSshPem(pem: String): ByteArray {
    val begin = "-----BEGIN OPENSSH PRIVATE KEY-----"
    val end = "-----END OPENSSH PRIVATE KEY-----"
    val start = pem.indexOf(begin)
    val finish = pem.indexOf(end)
    if (start < 0 || finish < 0 || finish < start)
      throw InvalidSshKeyException("not an OpenSSH private key (missing PEM markers)")
    val body = pem.substring(start + begin.length, finish).replace(Regex("\\s"), "")
    return try {
      Base64.getDecoder().decode(body)
    } catch (e: IllegalArgumentException) {
      throw InvalidSshKeyException("invalid base64 in OpenSSH private key", e)
    }
  }
}
