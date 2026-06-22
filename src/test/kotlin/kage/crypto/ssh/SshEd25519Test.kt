/**
 * Copyright 2022 The kage Authors. All rights reserved. Use of this source code is governed by
 * either an Apache 2.0 or MIT license at your discretion, that can be found in the LICENSE-APACHE
 * or LICENSE-MIT files respectively.
 */
package kage.kage.crypto.ssh

import com.google.common.truth.Truth.assertThat
import java.io.ByteArrayInputStream
import java.util.Random
import kage.Age
import kage.crypto.ssh.SshEd25519Identity
import kage.crypto.ssh.SshEd25519Recipient
import kage.crypto.ssh.SshKey
import kage.errors.InvalidSshKeyException
import kage.format.AgeFile
import org.bouncycastle.util.encoders.Base64
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows

class SshEd25519Test {
  // A fixed Ed25519 keypair generated with `ssh-keygen -t ed25519`, used so the tests exercise real
  // OpenSSH encodings rather than synthetic ones.
  private val publicKey =
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHG8mlXinVA7JAjGA18TFKWPJKS5j+PhrHswLtTBp/z/ kage-ssh-test"

  private val privateKey =
    """
    -----BEGIN OPENSSH PRIVATE KEY-----
    b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
    QyNTUxOQAAACBxvJpV4p1QOyQIxgNfExSljySkuY/j4ax7MC7Uwaf8/wAAAJBbYMrcW2DK
    3AAAAAtzc2gtZWQyNTUxOQAAACBxvJpV4p1QOyQIxgNfExSljySkuY/j4ax7MC7Uwaf8/w
    AAAECtl1fcB70WPqhj3qCXQWV/RQOWjMbMD5ybfLOgH+SwenG8mlXinVA7JAjGA18TFKWP
    JKS5j+PhrHswLtTBp/z/AAAADWthZ2Utc3NoLXRlc3Q=
    -----END OPENSSH PRIVATE KEY-----
    """
      .trimIndent()

  @Test
  fun testWrapUnwrap() {
    val recipient = SshEd25519Recipient.parse(publicKey)

    val fileKey = ByteArray(Age.FILE_KEY_SIZE)
    Random().nextBytes(fileKey)

    val stanza = recipient.wrap(fileKey).single()
    assertThat(stanza.type).isEqualTo("ssh-ed25519")
    assertThat(stanza.args).hasSize(2)

    val identity = SshKey.parseIdentity(privateKey)
    val unwrapped = identity.unwrap(listOf(stanza))
    assertThat(unwrapped.asList()).containsExactlyElementsIn(fileKey.asList())
  }

  @Test
  fun testRecipientFromIdentityRoundTrips() {
    val identity = SshKey.parseIdentity(privateKey)
    val recipient = (identity as SshEd25519Identity).recipient()

    val fileKey = ByteArray(Age.FILE_KEY_SIZE)
    Random().nextBytes(fileKey)

    val stanzas = recipient.wrap(fileKey)
    assertThat(identity.unwrap(stanzas).asList()).containsExactlyElementsIn(fileKey.asList())
  }

  @Test
  fun testAgeRoundTrip() {
    val recipient = SshKey.parseRecipient(publicKey)
    val identity = SshKey.parseIdentity(privateKey)

    val plaintext = "the quick brown fox jumps over the lazy dog".toByteArray()
    val ageFile = Age.encrypt(listOf(recipient), ByteArrayInputStream(plaintext))
    val decrypted = Age.decrypt(identity, ageFile).readBytes()

    assertThat(decrypted).isEqualTo(plaintext)
  }

  @Test
  fun testDecryptsReferenceAgeCiphertext() {
    // A binary age file produced by the reference age implementation with `age -R <pubKey>` over
    // the plaintext below. Decrypting it proves byte-level interop of the ssh-ed25519 stanza
    // (fingerprint tag, HKDF labels, tweak, salt order), which a kage-only round-trip cannot, since
    // a consistent deviation from age would pass that.
    val ageEncrypted =
      Base64.decode(
        """
        YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IHNzaC1lZDI1NTE5IGgwa0FBUSBxVFlOWmxPd1pFYjNz
        dVM1bFNmMUtKbkphN2hLZWUzUFlnbktLSnpFTUQwCnBkTittU0lxYTFmZ2tEZnNWY0RpbWdIc1ZL
        R2F2VmFDMTYyWW9ZTyt3a0kKLS0tIDJ5UmZiRmRtZ2h0MDlFQ2JXOHdvazFIbUY0cDgrTTZzanpS
        RmtLNTlEV0EKT+YuPQVK+quHMBG6sQ6nR2wO/7ZoWBVjoAlyhJO+1+L7XygyZhVN21hMSEu/43Tt
        AKmPLCnwnugrkbqhX961
        """
          .trimIndent()
      )

    val identity = SshKey.parseIdentity(privateKey)
    val ageFile = AgeFile.parse(ByteArrayInputStream(ageEncrypted))
    val decrypted = Age.decrypt(identity, ageFile).readBytes()

    assertThat(String(decrypted)).isEqualTo("kage ssh-ed25519 interop vector")
  }

  @Test
  fun testParseRejectsGarbage() {
    assertThrows<InvalidSshKeyException> { SshKey.parseRecipient("not a key") }
    assertThrows<InvalidSshKeyException> {
      SshKey.parseIdentity(
        "-----BEGIN OPENSSH PRIVATE KEY-----\nZZZ\n-----END OPENSSH PRIVATE KEY-----"
      )
    }
  }
}
