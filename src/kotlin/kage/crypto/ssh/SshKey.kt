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
import kage.errors.IncorrectPassphraseException
import kage.errors.InvalidSshKeyException
import kage.errors.UnsupportedSshKeyException
import org.bouncycastle.crypto.params.RSAKeyParameters
import org.bouncycastle.crypto.params.RSAPrivateCrtKeyParameters

/**
 * Parses SSH keys into kage [Recipient]s and [Identity]s.
 *
 * Public keys are read from a single `authorized_keys`-style line (`ssh-ed25519 AAAA... comment`).
 * Private keys are read from the OpenSSH private key format (`-----BEGIN OPENSSH PRIVATE
 * KEY-----`), encrypted or not. The [parseIdentity] overload taking a passphrase handles both cases
 * (an unencrypted key simply ignores the passphrase); encrypted keys support the ciphers
 * `ssh-keygen` actually produces via the `bcrypt` KDF (see [OpenSshCipher] and [BcryptPbkdf]).
 */
public object SshKey {
  private const val SSH_ED25519 = "ssh-ed25519"
  private const val SSH_RSA = "ssh-rsa"

  // The fixed OpenSSH private key magic: the ASCII "openssh-key-v1" followed by a NUL byte.
  private val AUTH_MAGIC = "openssh-key-v1".toByteArray(Charsets.US_ASCII).plus(0x00.toByte())

  // Ceiling on bcrypt kdf rounds accepted when decrypting, bounding the cost a hostile key file
  // can force. `ssh-keygen -a` defaults to 16-24.
  private const val MAX_KDF_ROUNDS = 1000L

  /** Parses an `authorized_keys`-style public key line into a [Recipient]. */
  public fun parseRecipient(authorizedKey: String): Recipient {
    val (type, _) = parseAuthorizedKey(authorizedKey)
    return when (type) {
      SSH_ED25519 -> SshEd25519Recipient.parse(authorizedKey)
      SSH_RSA -> SshRsaRecipient.parse(authorizedKey)
      else -> throw UnsupportedSshKeyException("unsupported SSH key type: $type")
    }
  }

  /**
   * Parses an unencrypted OpenSSH private key (PEM) into an [Identity].
   *
   * @throws UnsupportedSshKeyException if the key is passphrase-encrypted; use the overload taking
   *   a passphrase instead.
   */
  public fun parseIdentity(privateKey: String): Identity =
    decodeAndReadIdentity(privateKey, passphrase = null)

  /**
   * Parses an OpenSSH private key (PEM) into an [Identity]. If the key isn't passphrase-encrypted,
   * [passphrase] is ignored (not an error) so callers don't need to know in advance which case
   * they're in.
   */
  public fun parseIdentity(privateKey: String, passphrase: ByteArray): Identity =
    decodeAndReadIdentity(privateKey, passphrase)

  private fun decodeAndReadIdentity(privateKey: String, passphrase: ByteArray?): Identity {
    val blob = decodeOpenSshPem(privateKey)
    // Normalize low-level wire errors (e.g. truncation) to InvalidSshKeyException, but let the
    // exceptions we raise on purpose pass through unchanged.
    return try {
      readIdentity(blob, passphrase)
    } catch (e: InvalidSshKeyException) {
      throw e
    } catch (e: UnsupportedSshKeyException) {
      throw e
    } catch (e: Exception) {
      throw InvalidSshKeyException("malformed OpenSSH private key", e)
    }
  }

  private fun readIdentity(blob: ByteArray, passphrase: ByteArray?): Identity {
    val reader = SshWireReader(blob)

    val magic = reader.readRaw(AUTH_MAGIC.size)
    if (!magic.contentEquals(AUTH_MAGIC))
      throw InvalidSshKeyException("not an OpenSSH private key (bad magic)")

    val cipherName = String(reader.readString(), Charsets.US_ASCII)
    val kdfName = String(reader.readString(), Charsets.US_ASCII)
    val kdfOptions = reader.readString()
    val numKeys = reader.readUInt32()
    if (numKeys != 1L) throw UnsupportedSshKeyException("multi-key OpenSSH files are not supported")

    val publicKeyBlob = reader.readString()
    val encryptedOrPlainSection = reader.readString()

    val wasEncrypted = cipherName != "none" || kdfName != "none"
    val privateSection =
      if (!wasEncrypted) {
        encryptedOrPlainSection
      } else {
        if (passphrase == null)
          throw UnsupportedSshKeyException(
            "this key is passphrase-encrypted; call parseIdentity(privateKey, passphrase) instead"
          )
        if (kdfName != "bcrypt")
          throw UnsupportedSshKeyException("unsupported OpenSSH key kdf: $kdfName")
        decryptPrivateSection(cipherName, kdfOptions, passphrase, encryptedOrPlainSection)
      }

    val priv = SshWireReader(privateSection)
    val check1 = priv.readUInt32()
    val check2 = priv.readUInt32()
    if (check1 != check2) {
      // A wrong passphrase decrypts to garbage that fails this same check.
      if (wasEncrypted) throw IncorrectPassphraseException("incorrect passphrase")
      throw InvalidSshKeyException("OpenSSH private key checksum mismatch")
    }

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

  /**
   * Decrypts an encrypted private key section: derives a key+IV from [passphrase] via
   * `bcrypt_pbkdf` using the salt and round count packed into [kdfOptions] (`string salt, uint32
   * rounds`, per OpenSSH's `PROTOCOL.key`), then decrypts [ciphertext] with [cipherName].
   */
  private fun decryptPrivateSection(
    cipherName: String,
    kdfOptions: ByteArray,
    passphrase: ByteArray,
    ciphertext: ByteArray,
  ): ByteArray {
    if (passphrase.isEmpty()) throw IncorrectPassphraseException("empty passphrase")

    val options = SshWireReader(kdfOptions)
    val salt = options.readString()
    val rounds = options.readUInt32()
    if (rounds !in 1..MAX_KDF_ROUNDS)
      throw UnsupportedSshKeyException("bcrypt kdf rounds too large: $rounds")

    val keyAndIv =
      BcryptPbkdf.derive(passphrase, salt, OpenSshCipher.keyAndIvLength(cipherName), rounds.toInt())
    return OpenSshCipher.decrypt(cipherName, keyAndIv, ciphertext)
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
