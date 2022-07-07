/**
 * Copyright 2021 The kage Authors. All rights reserved. Use of this source code is governed by
 * either an Apache 2.0 or MIT license at your discretion, that can be found in the LICENSE-APACHE
 * or LICENSE-MIT files respectively.
 */
package kage

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
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import org.bouncycastle.util.encoders.Base64
import org.bouncycastle.util.encoders.Hex
import org.junit.Test

// TODO: Write some integration tests using another implementation of `age`
class AgeTest {
  private fun genX25519Identity(): Pair<X25519Recipient, X25519Identity> {
    val privateKey = ByteArray(X25519Recipient.KEY_LENGTH)
    SecureRandom().nextBytes(privateKey)
    val publicKey = X25519.scalarMult(privateKey, X25519.BASEPOINT)

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

    assertEquals("this is my file", decryptedOutput.toByteArray().decodeToString())
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

    assertEquals("this is my file", decryptedOutput.toByteArray().decodeToString())
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

    assertContentEquals(i, decryptedOutput.toByteArray())
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

    assertContentEquals(i, decryptedOutput.toByteArray())
  }

  @Test
  fun testEncryptDecryptAgeFile() {
    val (recipient, identity) = genX25519Identity()

    val bais = ByteArrayInputStream("this is my file".toByteArray())
    val ageFile = Age.encrypt(listOf(recipient), bais)

    val out = Age.decrypt(identity, ageFile)

    assertEquals(out.readAllBytes().decodeToString(), "this is my file")
  }

  @Test
  fun testEncryptDecryptEmptyPayload() {
    val (recipient, identity) = genX25519Identity()

    val bais = ByteArrayInputStream(ByteArray(0))
    val ageFile = Age.encrypt(listOf(recipient), bais)

    val out = Age.decrypt(identity, ageFile)

    assertContentEquals(ByteArray(0), out.readAllBytes())
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
    assertContentEquals(payload, out.readAllBytes())

    val otherOut = Age.decrypt(otherIdentity, ageFile)
    assertContentEquals(payload, otherOut.readAllBytes())
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
    assertContentEquals(payload, out.readAllBytes())
  }

  @Test
  fun testScryptIdentityIsTheOnlyIdentity() {
    val (recipient, _) = genX25519Identity()
    val scryptRecipient = ScryptRecipient("mypass1".toByteArray())

    val payload = ByteArray(1023)
    Random().nextBytes(payload)

    val bais = ByteArrayInputStream(payload)

    assertFailsWith<InvalidScryptRecipientException> {
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
    """.trimIndent()
      )

    // This is public key age1z2fw2ks7jp7ak3tjven6kxd53m7lxgmn9j7nrt0gfmewcr4sav9sp2n34j
    // but we don't parse bech32 yet
    val agePublicKey =
      Hex.decode("1292e55a1e907ddb45726667ab19b48efdf323732cbd31ade84ef2ec0eb0eb0b")
    // This is private key
    // AGE-SECRET-KEY-1M4FTVTZNTJKMXLW2Q6P3L5K2EZ3SFN856KNJFYNVY6UC6LPR0XYSKZV9EP
    // but we don't parse bech32 yet
    val agePrivateKey =
      Hex.decode("dd52b62c535cadb37dca06831fd2cac8a304ccf4d5a724926c26b98d7c237989")

    val identity = X25519Identity(agePrivateKey, agePublicKey)

    val ageFile = AgeFile.parse(ByteArrayInputStream(ageGoEncrypted))

    val decryptedStream = Age.decrypt(identity, ageFile)

    val decrypted = decryptedStream.readAllBytes().decodeToString()

    assertEquals("this was encrypted by age.go", decrypted)
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
    """.trimIndent()
      )

    val identity = ScryptIdentity("somepass".toByteArray())

    val ageFile = AgeFile.parse(ByteArrayInputStream(ageGoEncrypted))

    val decryptedStream = Age.decrypt(identity, ageFile)

    val decrypted = decryptedStream.readAllBytes().decodeToString()

    assertEquals("[scrypt] this was encrypted by age.go", decrypted)
  }

  @Test
  fun testEncryptToAgeGoX25519() {
    // This is public key age1z2fw2ks7jp7ak3tjven6kxd53m7lxgmn9j7nrt0gfmewcr4sav9sp2n34j
    // but we don't parse bech32 yet
    val agePublicKey =
      Hex.decode("1292e55a1e907ddb45726667ab19b48efdf323732cbd31ade84ef2ec0eb0eb0b")

    val recipient = X25519Recipient(agePublicKey)

    val ciphertextStream = ByteArrayOutputStream()

    val payload = "this was encrypted by kage"

    Age.encryptStream(
      listOf(recipient),
      ByteArrayInputStream(payload.toByteArray()),
      ciphertextStream
    )

    val ciphertext = Base64.toBase64String(ciphertextStream.toByteArray())

    // TODO: Test this using an integration test calling age.go
    println(ciphertext)
  }
}
