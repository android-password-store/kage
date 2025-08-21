/**
 * Copyright 2023 The kage Authors. All rights reserved. Use of this source code is governed by
 * either an Apache 2.0 or MIT license at your discretion, that can be found in the LICENSE-APACHE
 * or LICENSE-MIT files respectively.
 */
package kage.kage

import com.google.common.truth.Truth.assertThat
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import kage.Age
import kage.crypto.scrypt.ScryptIdentity
import kage.crypto.scrypt.ScryptRecipient
import kage.errors.ArmorCodingException
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows

class ArmorTest {

  val identity = ScryptIdentity("mypass".toByteArray())

  @Test
  fun testDecryptArmorPayload() {
    val encryptedInputStr =
      """
      |-----BEGIN AGE ENCRYPTED FILE-----
      |YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IHNjcnlwdCBEUXh3Qk95OWtmOEdBVFJH
      |Ukw4aE1RIDE4CnNlY1pRR011ekJpVjZvZUFhakhGZE8rcUtyRWtEN1c4b0hXbzhr
      |ZG5iekEKLS0tIEYzcXpHb2N4STExV0VEWnZtQUFpRXA4OXBLUWlWTTJnbkhPbEJs
      |Sy8vNVUKjYeREvMLfFR1ZFUCohjQnSP/d1n4hPuxTeFggWM94q6dhTr6qrvjBMPL
      |ec4AeigPelkT
      |-----END AGE ENCRYPTED FILE-----
      |"""
        .trimMargin()

    val decryptedOutput = ByteArrayOutputStream()

    val encryptedInput = ByteArrayInputStream(encryptedInputStr.toByteArray())

    Age.decryptStream(listOf(identity), encryptedInput, decryptedOutput)

    assertThat(decryptedOutput.toByteArray().decodeToString()).isEqualTo("this is my payload\n")
  }

  @Test
  fun testTrailingData() {
    val encryptedInputStr =
      """
      |-----BEGIN AGE ENCRYPTED FILE-----
      |YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IHNjcnlwdCBEUXh3Qk95OWtmOEdBVFJH
      |Ukw4aE1RIDE4CnNlY1pRR011ekJpVjZvZUFhakhGZE8rcUtyRWtEN1c4b0hXbzhr
      |ZG5iekEKLS0tIEYzcXpHb2N4STExV0VEWnZtQUFpRXA4OXBLUWlWTTJnbkhPbEJs
      |Sy8vNVUKjYeREvMLfFR1ZFUCohjQnSP/d1n4hPuxTeFggWM94q6dhTr6qrvjBMPL
      |ec4AeigPelkT
      |-----END AGE ENCRYPTED FILE-----
      |
      | trailing data
      |"""
        .trimMargin()

    val decryptedOutput = ByteArrayOutputStream()

    val encryptedInput = ByteArrayInputStream(encryptedInputStr.toByteArray())

    val error =
      assertThrows<ArmorCodingException> {
        Age.decryptStream(listOf(identity), encryptedInput, decryptedOutput)
      }

    assertThat(error).hasMessageThat().isEqualTo("trailing data after armored file")
  }

  @Test
  fun testTrailingWhitespaceData() {
    val encryptedInputStr =
      """
      |-----BEGIN AGE ENCRYPTED FILE-----
      |YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IHNjcnlwdCBEUXh3Qk95OWtmOEdBVFJH
      |Ukw4aE1RIDE4CnNlY1pRR011ekJpVjZvZUFhakhGZE8rcUtyRWtEN1c4b0hXbzhr
      |ZG5iekEKLS0tIEYzcXpHb2N4STExV0VEWnZtQUFpRXA4OXBLUWlWTTJnbkhPbEJs
      |Sy8vNVUKjYeREvMLfFR1ZFUCohjQnSP/d1n4hPuxTeFggWM94q6dhTr6qrvjBMPL
      |ec4AeigPelkT
      |-----END AGE ENCRYPTED FILE-----
      |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               
      |"""
        .trimMargin()

    val decryptedOutput = ByteArrayOutputStream()

    val encryptedInput = ByteArrayInputStream(encryptedInputStr.toByteArray())

    val error =
      assertThrows<ArmorCodingException> {
        Age.decryptStream(listOf(identity), encryptedInput, decryptedOutput)
      }

    assertThat(error).hasMessageThat().isEqualTo("too much trailing whitespace")
  }

  @Test
  fun testInvalidFirstLine() {
    val encryptedInputStr =
      """
      |-----BEGIN AGE ENCRYPTED FILE-----something else
      |YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IHNjcnlwdCBEUXh3Qk95OWtmOEdBVFJH
      |Ukw4aE1RIDE4CnNlY1pRR011ekJpVjZvZUFhakhGZE8rcUtyRWtEN1c4b0hXbzhr
      |ZG5iekEKLS0tIEYzcXpHb2N4STExV0VEWnZtQUFpRXA4OXBLUWlWTTJnbkhPbEJs
      |Sy8vNVUKjYeREvMLfFR1ZFUCohjQnSP/d1n4hPuxTeFggWM94q6dhTr6qrvjBMPL
      |ec4AeigPelkT
      |-----END AGE ENCRYPTED FILE-----
      |"""
        .trimMargin()

    val decryptedOutput = ByteArrayOutputStream()

    val encryptedInput = ByteArrayInputStream(encryptedInputStr.toByteArray())

    val error =
      assertThrows<ArmorCodingException> {
        Age.decryptStream(listOf(identity), encryptedInput, decryptedOutput)
      }

    assertThat(error)
      .hasMessageThat()
      .isEqualTo("invalid first line: -----BEGIN AGE ENCRYPTED FILE-----something else")
  }

  @Test
  fun testInvalidLineLength() {
    val encryptedInputStr =
      """
      |-----BEGIN AGE ENCRYPTED FILE-----
      |YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IHNjcnlwdCBEUXh3Qk95OWtmOEdBVFJHUkw4aE1RIDE4CnNlY1pRR011ekJpVjZvZUFhakhGZE8rcUtyRWtEN1c4b0hXbzhr
      |ZG5iekEKLS0tIEYzcXpHb2N4STExV0VEWnZtQUFpRXA4OXBLUWlWTTJnbkhPbEJs
      |Sy8vNVUKjYeREvMLfFR1ZFUCohjQnSP/d1n4hPuxTeFggWM94q6dhTr6qrvjBMPL
      |ec4AeigPelkT
      |-----END AGE ENCRYPTED FILE-----
      |"""
        .trimMargin()

    val decryptedOutput = ByteArrayOutputStream()

    val encryptedInput = ByteArrayInputStream(encryptedInputStr.toByteArray())

    val error =
      assertThrows<ArmorCodingException> {
        Age.decryptStream(listOf(identity), encryptedInput, decryptedOutput)
      }

    assertThat(error).hasMessageThat().isEqualTo("column limit exceeded")
  }

  @Test
  fun testInvalidFooter() {
    val encryptedInputStr =
      """
      |-----BEGIN AGE ENCRYPTED FILE-----
      |YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IHNjcnlwdCBEUXh3Qk95OWtmOEdBVFJH
      |Ukw4aE1RIDE4CnNlY1pRR011ekJpVjZvZUFhakhGZE8rcUtyRWtEN1c4b0hXbzhr
      |ZG5iekEKLS0tIEYzcXpHb2N4STExV0VEWnZtQUFpRXA4OXBLUWlWTTJnbkhPbEJs
      |Sy8vNVUKjYeREvMLfFR1ZFUCohjQnSP/d1n4hPuxTeFggWM94q6dhTr6qrvjBMPL
      |ec4AeigPelkT
      |-----END AGE ENCRYPTED FILE-----somethingelse
      |"""
        .trimMargin()

    val decryptedOutput = ByteArrayOutputStream()

    val encryptedInput = ByteArrayInputStream(encryptedInputStr.toByteArray())

    val error =
      assertThrows<ArmorCodingException> {
        Age.decryptStream(listOf(identity), encryptedInput, decryptedOutput)
      }

    assertThat(error).hasMessageThat().isEqualTo("invalid closing line")
  }

  @Test
  fun testEncryptDecryptArmor() {
    val recipient = ScryptRecipient("mypass".toByteArray(), workFactor = 10)

    val payload = "this is my payload"

    val encryptedOutput = ByteArrayOutputStream()

    Age.encryptStream(
      listOf(recipient),
      payload.byteInputStream(),
      encryptedOutput,
      generateArmor = true,
    )

    val decryptedOutput = ByteArrayOutputStream()

    val encryptedInput = ByteArrayInputStream(encryptedOutput.toByteArray())

    Age.decryptStream(listOf(identity), encryptedInput, decryptedOutput)

    assertThat(decryptedOutput.toString()).isEqualTo(payload)
  }
}
