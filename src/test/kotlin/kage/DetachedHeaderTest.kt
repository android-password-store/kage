/**
 * Copyright 2026 The kage Authors. All rights reserved. Use of this source code is governed by
 * either an Apache 2.0 or MIT license at your discretion, that can be found in the LICENSE-APACHE
 * or LICENSE-MIT files respectively.
 */
package kage

import com.google.common.truth.Truth.assertThat
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import kage.crypto.stream.ArmorOutputStream
import kage.crypto.x25519.X25519Identity
import kage.errors.IncorrectHMACException
import kage.errors.IncorrectIdentityException
import kage.errors.NoIdentitiesException
import kage.format.AgeHeader
import kage.format.AgeStanza
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows

class DetachedHeaderTest {

  private fun encrypt(identity: X25519Identity, payload: String): ByteArray {
    val out = ByteArrayOutputStream()
    Age.encryptStream(listOf(identity.recipient()), payload.byteInputStream(), out)
    return out.toByteArray()
  }

  private fun armor(binary: ByteArray): ByteArray {
    val out = ByteArrayOutputStream()
    ArmorOutputStream(out).use { armored -> armored.write(binary) }
    return out.toByteArray()
  }

  private fun serialize(header: AgeHeader): ByteArray {
    val out = ByteArrayOutputStream()
    out.bufferedWriter().use { writer -> header.write(writer) }
    return out.toByteArray()
  }

  @Test
  fun testDetachedHeaderRoundTrip() {
    val identity = X25519Identity.new()
    val ciphertext = encrypt(identity, "this is my file")

    val header = Age.extractHeader(ByteArrayInputStream(ciphertext))
    val fileKey = Age.decryptHeader(header, listOf(identity))

    assertThat(fileKey).hasLength(Age.FILE_KEY_SIZE)

    val decrypted = ByteArrayOutputStream()
    Age.decryptStream(
      listOf(InjectedFileKeyIdentity(fileKey)),
      ByteArrayInputStream(ciphertext),
      decrypted,
    )

    assertThat(decrypted.toByteArray().decodeToString()).isEqualTo("this is my file")
  }

  @Test
  fun testExtractHeaderAcceptsArmor() {
    val identity = X25519Identity.new()
    val ciphertext = encrypt(identity, "this is my file")

    val fromBinary = Age.extractHeader(ByteArrayInputStream(ciphertext))
    val fromArmor = Age.extractHeader(ByteArrayInputStream(armor(ciphertext)))

    assertThat(fromArmor).isEqualTo(fromBinary)
    assertThat(fromArmor.decodeToString()).startsWith("age-encryption.org/v1\n")
    assertThat(Age.decryptHeader(fromArmor, listOf(identity))).hasLength(Age.FILE_KEY_SIZE)
  }

  @Test
  fun testDecryptHeaderWithWrongIdentity() {
    val identity = X25519Identity.new()
    val otherIdentity = X25519Identity.new()
    val ciphertext = encrypt(identity, "this is my file")

    val header = Age.extractHeader(ByteArrayInputStream(ciphertext))

    assertThrows<IncorrectIdentityException> { Age.decryptHeader(header, listOf(otherIdentity)) }
    assertThrows<IncorrectIdentityException> {
      Age.decryptStream(
        listOf(otherIdentity),
        ByteArrayInputStream(ciphertext),
        ByteArrayOutputStream(),
      )
    }
  }

  @Test
  fun testDecryptHeaderWithTamperedMac() {
    val identity = X25519Identity.new()
    val ciphertext = encrypt(identity, "this is my file")

    val header = AgeHeader.parse(ByteArrayInputStream(ciphertext).buffered())
    val tampered = AgeHeader(header.recipients, ByteArray(header.mac.size))

    assertThrows<IncorrectHMACException> {
      Age.decryptHeader(serialize(tampered), listOf(identity))
    }
  }

  @Test
  fun testDecryptHeaderWithTamperedStanza() {
    val identity = X25519Identity.new()
    val otherIdentity = X25519Identity.new()

    val header =
      AgeHeader.parse(ByteArrayInputStream(encrypt(identity, "this is my file")).buffered())
    val otherHeader =
      AgeHeader.parse(ByteArrayInputStream(encrypt(otherIdentity, "this is my file")).buffered())
    val tampered = AgeHeader(otherHeader.recipients, header.mac)

    assertThrows<IncorrectHMACException> {
      Age.decryptHeader(serialize(tampered), listOf(otherIdentity))
    }
  }

  @Test
  fun testDecryptHeaderWithoutIdentities() {
    val identity = X25519Identity.new()
    val header = Age.extractHeader(ByteArrayInputStream(encrypt(identity, "this is my file")))

    assertThrows<NoIdentitiesException> { Age.decryptHeader(header, emptyList()) }
  }

  @Test
  fun testInjectedFileKeyIdentityIgnoresStanzas() {
    val fileKey = ByteArray(Age.FILE_KEY_SIZE) { it.toByte() }
    val identity = InjectedFileKeyIdentity(fileKey)

    assertThat(identity.unwrap(emptyList())).isEqualTo(fileKey)
    assertThat(identity.unwrap(listOf(AgeStanza("X25519", listOf("bogus"), ByteArray(32)))))
      .isEqualTo(fileKey)
  }
}
