/**
 * Copyright 2026 The kage Authors. All rights reserved. Use of this source code is governed by
 * either an Apache 2.0 or MIT license at your discretion, that can be found in the LICENSE-APACHE
 * or LICENSE-MIT files respectively.
 */
package kage.kage.crypto.ssh

import com.google.common.truth.Truth.assertThat
import java.io.ByteArrayOutputStream
import java.math.BigInteger
import java.util.Base64
import kage.crypto.ssh.SshKey
import kage.errors.InvalidSshKeyException
import kage.errors.UnsupportedSshKeyException
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows

class SshKeyTest {
  private fun sshString(value: ByteArray): ByteArray =
    ByteArrayOutputStream()
      .apply {
        write(value.size ushr 24)
        write(value.size ushr 16)
        write(value.size ushr 8)
        write(value.size)
        write(value)
      }
      .toByteArray()

  private fun sshBlob(vararg fields: ByteArray): ByteArray =
    ByteArrayOutputStream().apply { fields.forEach { write(sshString(it)) } }.toByteArray()

  private fun authorized(type: String, blob: ByteArray): String =
    "$type ${Base64.getEncoder().encodeToString(blob)}"

  private fun uint32(value: Long): ByteArray =
    byteArrayOf(
      (value ushr 24).toByte(),
      (value ushr 16).toByte(),
      (value ushr 8).toByte(),
      value.toByte(),
    )

  private fun encodePem(blob: ByteArray): String =
    "-----BEGIN OPENSSH PRIVATE KEY-----\n${Base64.getEncoder().encodeToString(blob)}\n-----END OPENSSH PRIVATE KEY-----"

  private fun privateKey(
    type: String,
    vararg fields: ByteArray,
    matchingChecks: Boolean = true,
  ): String {
    val section =
      ByteArrayOutputStream()
        .apply {
          write(uint32(1))
          write(uint32(if (matchingChecks) 1 else 2))
          write(sshString(type.toByteArray()))
          fields.forEach { write(sshString(it)) }
        }
        .toByteArray()
    val publicBlob = sshBlob(type.toByteArray())
    val blob =
      ByteArrayOutputStream()
        .apply {
          write("openssh-key-v1\u0000".toByteArray(Charsets.US_ASCII))
          write(sshString("none".toByteArray()))
          write(sshString("none".toByteArray()))
          write(sshString(byteArrayOf()))
          write(uint32(1))
          write(sshString(publicBlob))
          write(sshString(section))
        }
        .toByteArray()
    return encodePem(blob)
  }

  @Test
  fun parseRecipientRejectsUnsupportedAndMismatchedTypes() {
    val unknown = authorized("ssh-unknown", sshBlob("ssh-unknown".toByteArray()))
    assertThrows<UnsupportedSshKeyException> { SshKey.parseRecipient(unknown) }

    val mismatch = authorized("ssh-ed25519", sshBlob("ssh-rsa".toByteArray()))
    assertThrows<InvalidSshKeyException> { SshKey.parseRecipient(mismatch) }
    assertThrows<InvalidSshKeyException> { SshKey.parseAuthorizedKey("ssh-ed25519 %%%") }
    assertThrows<InvalidSshKeyException> { SshKey.parseAuthorizedKey("ssh-ed25519") }
  }

  @Test
  fun publicKeyBlobReadersValidateLengthsAndRsaSize() {
    assertThrows<InvalidSshKeyException> {
      SshKey.ed25519PublicKeyFromBlob(sshBlob("ssh-ed25519".toByteArray(), byteArrayOf(1)))
    }

    val tinyRsa =
      sshBlob(
        "ssh-rsa".toByteArray(),
        BigInteger.valueOf(3).toByteArray(),
        BigInteger.valueOf(7).toByteArray(),
      )
    assertThrows<UnsupportedSshKeyException> { SshKey.rsaPublicKeyFromBlob(tinyRsa) }

    val modulus = BigInteger.ONE.shiftLeft(2047).add(BigInteger.valueOf(123))
    val rsa =
      sshBlob(
        "ssh-rsa".toByteArray(),
        BigInteger.valueOf(65537).toByteArray(),
        modulus.toByteArray(),
      )
    assertThat(SshKey.rsaPublicKeyFromBlob(rsa).modulus).isEqualTo(modulus)
  }

  @Test
  fun parseIdentityRejectsMissingPemMarkersAndBadMagic() {
    assertThrows<InvalidSshKeyException> { SshKey.parseIdentity("not a private key") }
    assertThrows<InvalidSshKeyException> {
      SshKey.parseIdentity("-----END OPENSSH PRIVATE KEY----------BEGIN OPENSSH PRIVATE KEY-----")
    }
    assertThrows<InvalidSshKeyException> { SshKey.parseIdentity(encodePem(byteArrayOf(1, 2, 3))) }
  }

  @Test
  fun parseIdentityRejectsMultipleKeys() {
    val blob =
      ByteArrayOutputStream()
        .apply {
          write("openssh-key-v1\u0000".toByteArray(Charsets.US_ASCII))
          write(sshString("none".toByteArray()))
          write(sshString("none".toByteArray()))
          write(sshString(byteArrayOf()))
          write(uint32(2))
        }
        .toByteArray()
    assertThrows<UnsupportedSshKeyException> { SshKey.parseIdentity(encodePem(blob)) }
  }

  @Test
  fun parseIdentityRejectsInvalidPrivateSections() {
    assertThrows<InvalidSshKeyException> {
      SshKey.parseIdentity(privateKey("ssh-unknown", matchingChecks = false))
    }
    assertThrows<InvalidSshKeyException> {
      SshKey.parseIdentity(privateKey("ssh-ed25519", ByteArray(31), ByteArray(64)))
    }
    assertThrows<InvalidSshKeyException> {
      SshKey.parseIdentity(privateKey("ssh-ed25519", ByteArray(32), ByteArray(63)))
    }
    assertThrows<UnsupportedSshKeyException> {
      SshKey.parseIdentity(privateKey("ssh-unknown"))
    }
    assertThrows<UnsupportedSshKeyException> {
      SshKey.parseIdentity(
        privateKey(
          "ssh-rsa",
          BigInteger.ONE.toByteArray(),
          BigInteger.ONE.toByteArray(),
          BigInteger.ONE.toByteArray(),
          BigInteger.ONE.toByteArray(),
          BigInteger.ONE.toByteArray(),
          BigInteger.ONE.toByteArray(),
        )
      )
    }
  }

  private fun identityBlob(
    cipher: String = "none",
    kdf: String = "none",
    kdfOptions: ByteArray = byteArrayOf(),
    publicBlob: ByteArray,
    privateSection: ByteArray,
  ): ByteArray =
    ByteArrayOutputStream()
      .apply {
        write("openssh-key-v1\u0000".toByteArray(Charsets.US_ASCII))
        write(sshString(cipher.toByteArray()))
        write(sshString(kdf.toByteArray()))
        write(sshString(kdfOptions))
        write(uint32(1))
        write(sshString(publicBlob))
        write(sshString(privateSection))
      }
      .toByteArray()

  private fun ed25519Section(publicKey: ByteArray, privateKeyBytes: ByteArray): ByteArray =
    ByteArrayOutputStream()
      .apply {
        write(uint32(1))
        write(uint32(1))
        write(sshString("ssh-ed25519".toByteArray()))
        write(sshString(publicKey))
        write(sshString(privateKeyBytes))
      }
      .toByteArray()

  @Test
  fun parseIdentityRejectsFullLengthBadMagicAndMissingEndMarker() {
    assertThrows<InvalidSshKeyException> { SshKey.parseIdentity(encodePem(ByteArray(32))) }
    assertThrows<InvalidSshKeyException> {
      SshKey.parseIdentity("-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA")
    }
  }

  @Test
  fun parseIdentityRejectsUnsupportedKdfAndExcessiveBcryptRounds() {
    val unsupportedKdf =
      identityBlob(
        cipher = "aes256-ctr",
        kdf = "argon2",
        publicBlob = sshBlob("ssh-ed25519".toByteArray()),
        privateSection = ByteArray(16),
      )
    assertThrows<UnsupportedSshKeyException> {
      SshKey.parseIdentity(encodePem(unsupportedKdf), "passphrase".toByteArray())
    }

    val roundsTooSmall =
      ByteArrayOutputStream()
        .apply {
          write(sshString(ByteArray(16)))
          write(uint32(0))
        }
        .toByteArray()
    val excessiveRounds =
      identityBlob(
        cipher = "aes256-ctr",
        kdf = "bcrypt",
        kdfOptions = roundsTooSmall,
        publicBlob = sshBlob("ssh-ed25519".toByteArray()),
        privateSection = ByteArray(16),
      )
    assertThrows<UnsupportedSshKeyException> {
      SshKey.parseIdentity(encodePem(excessiveRounds), "passphrase".toByteArray())
    }
  }

  @Test
  fun parseIdentityRejectsEd25519PublicKeyMismatches() {
    val sectionPublic = ByteArray(32) { 2 }
    val privateKeyBytes = ByteArray(32) + sectionPublic

    val outerMismatch =
      identityBlob(
        publicBlob = sshBlob("ssh-ed25519".toByteArray(), ByteArray(32) { 1 }),
        privateSection = ed25519Section(sectionPublic, privateKeyBytes),
      )
    assertThrows<InvalidSshKeyException> { SshKey.parseIdentity(encodePem(outerMismatch)) }

    val seedMismatch =
      identityBlob(
        publicBlob = sshBlob("ssh-ed25519".toByteArray(), sectionPublic),
        privateSection = ed25519Section(sectionPublic, privateKeyBytes),
      )
    assertThrows<InvalidSshKeyException> { SshKey.parseIdentity(encodePem(seedMismatch)) }
  }

  @Test
  fun parseIdentityRejectsRsaPublicKeyMismatch() {
    val n = BigInteger.ONE.shiftLeft(2047).add(BigInteger.valueOf(123))
    val e = BigInteger.valueOf(65537)
    val section =
      ByteArrayOutputStream()
        .apply {
          write(uint32(1))
          write(uint32(1))
          write(sshString("ssh-rsa".toByteArray()))
          listOf(n, e, BigInteger.TEN, BigInteger.ONE, BigInteger.TWO, BigInteger.TWO).forEach {
            write(sshString(it.toByteArray()))
          }
        }
        .toByteArray()
    val blob =
      identityBlob(
        publicBlob =
          sshBlob("ssh-rsa".toByteArray(), e.toByteArray(), n.add(BigInteger.ONE).toByteArray()),
        privateSection = section,
      )
    assertThrows<InvalidSshKeyException> { SshKey.parseIdentity(encodePem(blob)) }

    val exponentMismatch =
      identityBlob(
        publicBlob =
          sshBlob("ssh-rsa".toByteArray(), BigInteger.valueOf(3).toByteArray(), n.toByteArray()),
        privateSection = section,
      )
    assertThrows<InvalidSshKeyException> { SshKey.parseIdentity(encodePem(exponentMismatch)) }
  }
}
