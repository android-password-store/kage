/**
 * Copyright 2022 The kage Authors. All rights reserved. Use of this source code is governed by
 * either an Apache 2.0 or MIT license at your discretion, that can be found in the LICENSE-APACHE
 * or LICENSE-MIT files respectively.
 */
package kage.crypto.ssh

import kage.Identity
import kage.crypto.ssh.SshRsaRecipient.Companion.SSH_RSA_STANZA_TYPE
import kage.errors.IncorrectIdentityException
import kage.errors.SshIdentityException
import kage.format.AgeStanza
import kage.multiUnwrap
import org.bouncycastle.crypto.params.RSAKeyParameters
import org.bouncycastle.crypto.params.RSAPrivateCrtKeyParameters

/**
 * An [Identity] backed by an SSH RSA private key, able to unwrap `ssh-rsa` stanzas produced by
 * [SshRsaRecipient] or by the reference age implementation.
 *
 * Construct one with [SshKey.parseIdentity]; the raw-key constructor is internal so callers go
 * through key parsing.
 */
public class SshRsaIdentity
internal constructor(
  private val sshKeyBlob: ByteArray,
  private val privateKey: RSAPrivateCrtKeyParameters,
) : Identity {

  private val ourFingerprint: String = sshFingerprint(sshKeyBlob)

  private fun unwrapSingle(stanza: AgeStanza): ByteArray {
    if (stanza.type != SSH_RSA_STANZA_TYPE) throw IncorrectIdentityException()

    // The single arg is the fingerprint of the key the stanza was wrapped to. If it is not ours the
    // stanza is for a different recipient, and a different identity should get a chance to try it.
    if (stanza.args.size != 1 || stanza.args[0] != ourFingerprint)
      throw IncorrectIdentityException()

    try {
      val oaep = SshRsaRecipient.oaep()
      oaep.init(false, privateKey)
      return oaep.processBlock(stanza.body, 0, stanza.body.size)
    } catch (err: Exception) {
      throw SshIdentityException("Error occurred while unwrapping stanza", err)
    }
  }

  override fun unwrap(stanzas: List<AgeStanza>): ByteArray = multiUnwrap(::unwrapSingle, stanzas)

  public fun recipient(): SshRsaRecipient {
    val publicKey = RSAKeyParameters(false, privateKey.modulus, privateKey.publicExponent)
    return SshRsaRecipient(sshKeyBlob, publicKey)
  }
}
