/**
 * Copyright 2022 The kage Authors. All rights reserved. Use of this source code is governed by
 * either an Apache 2.0 or MIT license at your discretion, that can be found in the LICENSE-APACHE
 * or LICENSE-MIT files respectively.
 */
package kage.crypto.ssh

import kage.Recipient
import kage.errors.InvalidSshKeyException
import kage.format.AgeStanza
import org.bouncycastle.crypto.digests.SHA256Digest
import org.bouncycastle.crypto.encodings.OAEPEncoding
import org.bouncycastle.crypto.engines.RSAEngine
import org.bouncycastle.crypto.params.RSAKeyParameters

/**
 * A [Recipient] that wraps the file key to an SSH RSA public key, producing an `ssh-rsa` stanza
 * compatible with the reference age implementation.
 *
 * The file key is encrypted with RSA-OAEP (SHA-256, MGF1-SHA256, label
 * `age-encryption.org/v1/ssh-rsa`), exactly as age does.
 *
 * Construct one with [parse] (or via [SshRsaIdentity.recipient]); the raw-key constructor is
 * internal so callers go through key parsing.
 */
public class SshRsaRecipient
internal constructor(
  private val sshKeyBlob: ByteArray,
  private val publicKey: RSAKeyParameters,
) : Recipient {

  override fun wrap(fileKey: ByteArray): List<AgeStanza> {
    val oaep = oaep()
    oaep.init(true, publicKey)
    val wrappedKey = oaep.processBlock(fileKey, 0, fileKey.size)

    val stanza = AgeStanza(SSH_RSA_STANZA_TYPE, listOf(sshFingerprint(sshKeyBlob)), wrappedKey)
    return listOf(stanza)
  }

  public companion object {
    internal const val SSH_RSA_STANZA_TYPE = "ssh-rsa"
    internal const val SSH_RSA_LABEL = "age-encryption.org/v1/ssh-rsa"

    // age (like OpenSSH and current best practice) rejects RSA keys below 2048 bits.
    internal const val MIN_RSA_BITS = 2048

    /**
     * Builds the RSA-OAEP scheme age uses for `ssh-rsa`: SHA-256 as the hash, MGF1 also over
     * SHA-256, and the age label as the OAEP encoding parameter. Using the BouncyCastle lightweight
     * API (rather than a JCA `Cipher`) keeps the MGF1 digest pinned to SHA-256 on every platform —
     * some JCA providers, notably Android's, silently fall back to MGF1-SHA1 and break interop.
     */
    internal fun oaep(): OAEPEncoding =
      OAEPEncoding(RSAEngine(), SHA256Digest(), SHA256Digest(), SSH_RSA_LABEL.toByteArray())

    /** Parses a single `authorized_keys`-style `ssh-rsa AAAA... [comment]` line. */
    public fun parse(authorizedKey: String): SshRsaRecipient {
      val (type, blob) = SshKey.parseAuthorizedKey(authorizedKey)
      if (type != SSH_RSA_STANZA_TYPE) throw InvalidSshKeyException("not an ssh-rsa key")
      val publicKey = SshKey.rsaPublicKeyFromBlob(blob)
      return SshRsaRecipient(blob, publicKey)
    }
  }
}
