/**
 * Copyright 2022 The kage Authors. All rights reserved. Use of this source code is governed by
 * either an Apache 2.0 or MIT license at your discretion, that can be found in the LICENSE-APACHE
 * or LICENSE-MIT files respectively.
 */
package kage.crypto.ssh

import java.security.SecureRandom
import kage.Recipient
import kage.crypto.stream.ChaCha20Poly1305
import kage.crypto.x25519.X25519
import kage.errors.InvalidSshKeyException
import kage.format.AgeStanza
import kage.utils.encodeBase64

/**
 * A [Recipient] that wraps the file key to an SSH Ed25519 public key, producing an `ssh-ed25519`
 * stanza compatible with the reference age implementation.
 *
 * The Ed25519 public key is converted to its Curve25519 form and an X25519 key agreement is run
 * with a fresh ephemeral key, mixed with a per-key tweak derived from the SSH key, exactly as age
 * does.
 *
 * Construct one with [parse] (or via [SshEd25519Identity.recipient]); the raw-bytes constructor is
 * internal so callers go through key parsing.
 */
public class SshEd25519Recipient
internal constructor(
  private val sshKeyBlob: ByteArray,
  private val ed25519PublicKey: ByteArray,
) : Recipient {

  private val curvePublicKey: ByteArray = Ed25519Conversions.publicKeyToCurve25519(ed25519PublicKey)

  override fun wrap(fileKey: ByteArray): List<AgeStanza> {
    val ephemeralSecret = ByteArray(EPHEMERAL_SECRET_LEN)
    SecureRandom().nextBytes(ephemeralSecret)

    val ourPublicKey = X25519.scalarMultBase(ephemeralSecret)

    val label = SSH_ED25519_LABEL.toByteArray()

    var sharedSecret = X25519.scalarMult(ephemeralSecret, curvePublicKey)
    val tweak = hkdfSha256(sshKeyBlob, EMPTY, label, CURVE25519_KEY_LEN)
    sharedSecret = X25519.scalarMult(tweak, sharedSecret)

    val salt = ourPublicKey.plus(curvePublicKey)
    val wrappingKey = hkdfSha256(salt, sharedSecret, label, CURVE25519_KEY_LEN)

    val wrappedKey = ChaCha20Poly1305.aeadEncrypt(wrappingKey, fileKey)

    val stanza =
      AgeStanza(
        SSH_ED25519_STANZA_TYPE,
        listOf(sshFingerprint(sshKeyBlob), ourPublicKey.encodeBase64()),
        wrappedKey,
      )

    return listOf(stanza)
  }

  public companion object {
    internal const val SSH_ED25519_STANZA_TYPE = "ssh-ed25519"
    internal const val SSH_ED25519_LABEL = "age-encryption.org/v1/ssh-ed25519"
    internal const val CURVE25519_KEY_LEN = 32 // bytes
    internal const val EPHEMERAL_SECRET_LEN = 32 // bytes
    private val EMPTY = ByteArray(0)

    /** Parses a single `authorized_keys`-style `ssh-ed25519 AAAA... [comment]` line. */
    public fun parse(authorizedKey: String): SshEd25519Recipient {
      val (type, blob) = SshKey.parseAuthorizedKey(authorizedKey)
      if (type != SSH_ED25519_STANZA_TYPE) throw InvalidSshKeyException("not an ssh-ed25519 key")
      val publicKey = SshKey.ed25519PublicKeyFromBlob(blob)
      return SshEd25519Recipient(blob, publicKey)
    }
  }
}
