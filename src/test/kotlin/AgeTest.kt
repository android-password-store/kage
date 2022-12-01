/**
 * Copyright 2022 The kage Authors. All rights reserved. Use of this source code is governed by
 * either an Apache 2.0 or MIT license at your discretion, that can be found in the LICENSE-APACHE
 * or LICENSE-MIT files respectively.
 */
package kage

import com.google.common.truth.Truth.assertThat
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.security.SecureRandom
import java.util.Random
import kage.crypto.scrypt.ScryptIdentity
import kage.crypto.scrypt.ScryptRecipient
import kage.crypto.stream.EncryptOutputStream.Companion.CHUNK_SIZE
import kage.crypto.x25519.X25519
import kage.crypto.x25519.X25519Identity
import kage.crypto.x25519.X25519Recipient
import kage.errors.InvalidScryptRecipientException
import kage.format.AgeFile
import org.bouncycastle.util.encoders.Base64
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows

class AgeTest {
  private fun genX25519Identity(): Pair<X25519Recipient, X25519Identity> {
    val privateKey = ByteArray(X25519Recipient.KEY_LENGTH)
    SecureRandom().nextBytes(privateKey)
    val publicKey = X25519.scalarMultBase(privateKey)

    return Pair(X25519Recipient(publicKey), X25519Identity(privateKey, publicKey))
  }

  @Test
  fun testEncryptDecryptScrypt() {
    val recipients = listOf(ScryptRecipient("mypass1".toByteArray(), workFactor = 2))

    val bais = ByteArrayInputStream("this is my file".toByteArray())
    val baos = ByteArrayOutputStream()

    Age.encryptStream(recipients, bais, baos, generateArmor = false)

    val identity = ScryptIdentity("mypass1".toByteArray())

    val encryptedInput = ByteArrayInputStream(baos.toByteArray())
    val decryptedOutput = ByteArrayOutputStream()

    Age.decryptStream(listOf(identity), encryptedInput, decryptedOutput)

    assertThat(decryptedOutput.toByteArray().decodeToString()).isEqualTo("this is my file")
  }

  @Test
  fun testEncryptDecryptX25519() {
    val (recipient, identity) = genX25519Identity()

    val recipients = listOf(recipient)

    val bais = ByteArrayInputStream("this is my file".toByteArray())
    val baos = ByteArrayOutputStream()

    Age.encryptStream(recipients, bais, baos)

    val encryptedInput = ByteArrayInputStream(baos.toByteArray())
    val decryptedOutput = ByteArrayOutputStream()

    Age.decryptStream(listOf(identity), encryptedInput, decryptedOutput)

    assertThat(decryptedOutput.toByteArray().decodeToString()).isEqualTo("this is my file")
  }

  @Test
  fun testScryptEncryptDecryptExactBlockSizeMultiple() {
    val (recipient, identity) = genX25519Identity()

    // Encrypt exactly 2 chunks
    val i = ByteArray(CHUNK_SIZE * 2)
    Random().nextBytes(i)

    val bais = ByteArrayInputStream(i)
    val baos = ByteArrayOutputStream()

    Age.encryptStream(listOf(recipient), bais, baos)

    val encryptedInput = ByteArrayInputStream(baos.toByteArray())
    val decryptedOutput = ByteArrayOutputStream()

    Age.decryptStream(listOf(identity), encryptedInput, decryptedOutput)

    assertThat(decryptedOutput.toByteArray()).asList().containsExactlyElementsIn(i.asList())
  }

  @Test
  fun testScryptEncryptDecryptExactBlock() {
    val (recipient, identity) = genX25519Identity()

    // Encrypt exactly 1 chunks
    val i = ByteArray(CHUNK_SIZE)
    Random().nextBytes(i)

    val bais = ByteArrayInputStream(i)
    val baos = ByteArrayOutputStream()

    Age.encryptStream(listOf(recipient), bais, baos)

    val encryptedInput = ByteArrayInputStream(baos.toByteArray())
    val decryptedOutput = ByteArrayOutputStream()

    Age.decryptStream(listOf(identity), encryptedInput, decryptedOutput)

    assertThat(decryptedOutput.toByteArray()).asList().containsExactlyElementsIn(i.asList())
  }

  @Test
  fun testEncryptDecryptAgeFile() {
    val (recipient, identity) = genX25519Identity()

    val bais = ByteArrayInputStream("this is my file".toByteArray())
    val ageFile = Age.encrypt(listOf(recipient), bais)

    val out = Age.decrypt(identity, ageFile)

    assertThat(out.readAllBytes().decodeToString()).isEqualTo("this is my file")
  }

  @Test
  fun testEncryptDecryptEmptyPayload() {
    val (recipient, identity) = genX25519Identity()

    val bais = ByteArrayInputStream(ByteArray(0))
    val ageFile = Age.encrypt(listOf(recipient), bais)

    val out = Age.decrypt(identity, ageFile)

    assertThat(out.readAllBytes()).hasLength(0)
  }

  @Test
  fun testTriesMultipleIdentities() {
    val (recipient, identity) = genX25519Identity()
    val (otherRecipient, otherIdentity) = genX25519Identity()

    val payload = ByteArray(1023)
    Random().nextBytes(payload)

    val bais = ByteArrayInputStream(payload)
    val ageFile = Age.encrypt(listOf(otherRecipient, recipient), bais)

    val out = Age.decrypt(identity, ageFile)
    assertThat(out.readAllBytes()).asList().containsExactlyElementsIn(payload.asList())

    val otherOut = Age.decrypt(otherIdentity, ageFile)
    assertThat(otherOut.readAllBytes()).asList().containsExactlyElementsIn(payload.asList())
  }

  @Test
  fun testTriesMultipleIdentitiesWhenNotAllDecrypt() {
    val (recipient, identity) = genX25519Identity()
    val (_, otherIdentity) = genX25519Identity()

    val payload = ByteArray(1023)
    Random().nextBytes(payload)

    val bais = ByteArrayInputStream(payload)
    val ageFile = Age.encrypt(listOf(recipient), bais)

    val out = Age.decrypt(listOf(otherIdentity, identity), ageFile)
    assertThat(out.readAllBytes()).asList().containsExactlyElementsIn(payload.asList())
  }

  @Test
  fun testScryptIdentityIsTheOnlyIdentity() {
    val (recipient, _) = genX25519Identity()
    val scryptRecipient = ScryptRecipient("mypass1".toByteArray())

    val payload = ByteArray(1023)
    Random().nextBytes(payload)

    val bais = ByteArrayInputStream(payload)

    assertThrows<InvalidScryptRecipientException> {
      Age.encrypt(listOf(recipient, scryptRecipient), bais)
    }
  }

  @Test
  fun testDecryptAgeGoAgeFileX25519() {
    val ageGoEncrypted =
      Base64.decode(
        """
      YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IFgyNTUxOSB0YWtyekFwWXdUWXc4TVBPcTlyMUU3UUpl
      S0dQR3RRbURubzJ5L0k5WERFCms5ZnlnMVg3WXVUeXdOU2NlYnExeWV0aXJLanpuMjBUZWk0VlFv
      WUZSR28KLS0tICtlcGZtVE13TmdVMjZrdVZLVUlTYXlWQXpDV200a0ZwNnN2eWk1Wk1VdmsKGhQA
      6bs5tBCG4FteXxjzEzxWhw4opD1bsn9vUqSXTqQN0lt9vgoXYPT8kgBAfQFKhWngGwIrYVzHslpq
    """
          .trimIndent()
      )

    val agePrivateKey =
      X25519Identity.decode(
        "AGE-SECRET-KEY-1M4FTVTZNTJKMXLW2Q6P3L5K2EZ3SFN856KNJFYNVY6UC6LPR0XYSKZV9EP"
      )

    val ageFile = AgeFile.parse(ByteArrayInputStream(ageGoEncrypted))

    val decryptedStream = Age.decrypt(agePrivateKey, ageFile)

    val decrypted = decryptedStream.readAllBytes().decodeToString()

    assertThat(decrypted).isEqualTo("this was encrypted by age.go")
  }

  @Test
  fun testDecryptAgeGoAgeFileScrypt() {
    val ageGoEncrypted =
      Base64.decode(
        """
      YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IHNjcnlwdCAxeTNqOTFEZU1WZ051WjFPQlVCbEJnIDE4
      CnI3Nm1kekNyTWphdTU2MFBlOVRJeU41ZklVNkFqOVdXQStWNzFxaDJ2Z00KLS0tIFdJaU9UNUVz
      NjViOE1CbEU5ZHVTOHZLWlJLNjQvZE5KSzRQbkRzTWtxaGsKPyFHbFyyZBLyV8FdaFVi/qIBFclK
      3Z1g750U9RBWS/vY33fIBOjRrnzj5scCgrI1OI0U5Etx91NUXSpALiDXCLtMpKQ1
    """
          .trimIndent()
      )

    val identity = ScryptIdentity("somepass".toByteArray())

    val ageFile = AgeFile.parse(ByteArrayInputStream(ageGoEncrypted))

    val decryptedStream = Age.decrypt(identity, ageFile)

    val decrypted = decryptedStream.readAllBytes().decodeToString()

    assertThat(decrypted).isEqualTo("[scrypt] this was encrypted by age.go")
  }

  @Test
  fun testEncryptToAgeGoX25519() {
    val agePublicKey =
      X25519Recipient.decode("age1z2fw2ks7jp7ak3tjven6kxd53m7lxgmn9j7nrt0gfmewcr4sav9sp2n34j")

    val ciphertextStream = ByteArrayOutputStream()

    val payload = "this was encrypted by kage"

    Age.encryptStream(
      listOf(agePublicKey),
      ByteArrayInputStream(payload.toByteArray()),
      ciphertextStream
    )

    val ciphertext = Base64.toBase64String(ciphertextStream.toByteArray())

    // TODO: Test this using an integration test calling age.go
    println(ciphertext)
  }
}
