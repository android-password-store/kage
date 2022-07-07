/**
 * Copyright 2021 The kage Authors. All rights reserved. Use of this source code is governed by
 * either an Apache 2.0 or MIT license at your discretion, that can be found in the LICENSE-APACHE
 * or LICENSE-MIT files respectively.
 */
package kage

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.util.*
import kage.crypto.chacha20.ChaCha20Poly1305OutputStream
import kage.crypto.scrypt.ScryptRecipient
import kage.crypto.x25519.X25519Recipient
import org.bouncycastle.util.encoders.Hex
import org.junit.Test

// TODO: Write some integration tests using another implementation of `age`
class AgeTest {
  @Test
  fun testEncryptDoesNotThrow() {
    val recipients = listOf(ScryptRecipient("mypass1".toByteArray(), 18))

    val bais = ByteArrayInputStream("this is my file".toByteArray())
    val baos = ByteArrayOutputStream()

    Age.encrypt(recipients, bais, baos, generateArmor = false)

    // println(Base64.getEncoder().encodeToString(baos.toByteArray()))
    // TODO: Test this better when `decrypt` is implemented
  }

  @Test
  fun testScryptEncryptExactBlockSizeDoesNotThrow() {
    // Encrypt exactly 2 chunks
    val i = ByteArray(ChaCha20Poly1305OutputStream.CHUNK_SIZE * 2)
    i.fill("0".toByte())
    val bais = ByteArrayInputStream(i)
    val recipients = listOf(ScryptRecipient("mypass2".toByteArray(), 18))
    val baos = ByteArrayOutputStream()

    Age.encrypt(recipients, bais, baos, generateArmor = false)

    //        println(Base64.getEncoder().encodeToString(baos.toByteArray()))
    // TODO: Test this better when `decrypt` is implemented
  }

  @Test
  fun testX25519EncryptDoesNotThrow() {
    val publicKey = Hex.decode("1292e55a1e907ddb45726667ab19b48efdf323732cbd31ade84ef2ec0eb0eb0b")

    val recipients = listOf(X25519Recipient(publicKey))

    val bais = ByteArrayInputStream("this is my file".toByteArray())
    val baos = ByteArrayOutputStream()

    Age.encrypt(recipients, bais, baos, generateArmor = false)

    println(Base64.getEncoder().encodeToString(baos.toByteArray()))
    // TODO: Test this better when `decrypt` is implemented
  }
}
