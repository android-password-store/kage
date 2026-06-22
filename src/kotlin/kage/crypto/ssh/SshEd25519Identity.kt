/**
 * Copyright 2022 The kage Authors. All rights reserved. Use of this source code is governed by
 * either an Apache 2.0 or MIT license at your discretion, that can be found in the LICENSE-APACHE
 * or LICENSE-MIT files respectively.
 */
package kage.crypto.ssh

import kage.Age
import kage.Identity
import kage.crypto.ssh.SshEd25519Recipient.Companion.CURVE25519_KEY_LEN
import kage.crypto.ssh.SshEd25519Recipient.Companion.SSH_ED25519_LABEL
import kage.crypto.ssh.SshEd25519Recipient.Companion.SSH_ED25519_STANZA_TYPE
import kage.crypto.stream.ChaCha20Poly1305
import kage.crypto.x25519.X25519
import kage.errors.IncorrectIdentityException
import kage.errors.SshIdentityException
import kage.format.AgeStanza
import kage.multiUnwrap
import kage.utils.decodeBase64

/**
 * An [Identity] backed by an SSH Ed25519 private key, able to unwrap `ssh-ed25519` stanzas produced
 * by [SshEd25519Recipient] or by the reference age implementation.
 *
 * Construct one with [SshKey.parseIdentity]; the raw-bytes constructor is internal so callers go
 * through key parsing.
 */
public class SshEd25519Identity
internal constructor(
  private val sshKeyBlob: ByteArray,
  ed25519PrivateSeed: ByteArray,
  private val ed25519PublicKey: ByteArray,
) : Identity {

  private val curveSecret: ByteArray =
    Ed25519Conversions.privateSeedToCurve25519(ed25519PrivateSeed)
  private val curvePublicKey: ByteArray = X25519.scalarMultBase(curveSecret)
  private val ourFingerprint: String = sshFingerprint(sshKeyBlob)

  private fun unwrapSingle(stanza: AgeStanza): ByteArray {
    if (stanza.type != SSH_ED25519_STANZA_TYPE) throw IncorrectIdentityException()

    // The first arg is the fingerprint of the key the stanza was wrapped to. If it is not ours the
    // stanza is for a different recipient, and a different identity should get a chance to try it.
    if (stanza.args.isEmpty() || stanza.args[0] != ourFingerprint)
      throw IncorrectIdentityException()

    try {
      if (stanza.args.size != 2) throw SshIdentityException("invalid ssh-ed25519 recipient block")

      val ephemeralPublicKey = stanza.args[1].decodeBase64()
      if (ephemeralPublicKey.size != CURVE25519_KEY_LEN)
        throw SshIdentityException("invalid ssh-ed25519 recipient block")

      val label = SSH_ED25519_LABEL.toByteArray()

      var sharedSecret = X25519.scalarMult(curveSecret, ephemeralPublicKey)
      val tweak = hkdfSha256(sshKeyBlob, EMPTY, label, CURVE25519_KEY_LEN)
      sharedSecret = X25519.scalarMult(tweak, sharedSecret)

      val salt = ephemeralPublicKey.plus(curvePublicKey)
      val wrappingKey = hkdfSha256(salt, sharedSecret, label, CURVE25519_KEY_LEN)

      return ChaCha20Poly1305.aeadDecrypt(wrappingKey, stanza.body, Age.FILE_KEY_SIZE)
    } catch (err: Exception) {
      if (err is SshIdentityException) throw err
      throw SshIdentityException("Error occurred while unwrapping stanza", err)
    }
  }

  override fun unwrap(stanzas: List<AgeStanza>): ByteArray = multiUnwrap(::unwrapSingle, stanzas)

  public fun recipient(): SshEd25519Recipient = SshEd25519Recipient(sshKeyBlob, ed25519PublicKey)

  private companion object {
    private val EMPTY = ByteArray(0)
  }
}
