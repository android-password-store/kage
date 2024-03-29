/**
 * Copyright 2022 The kage Authors. All rights reserved. Use of this source code is governed by
 * either an Apache 2.0 or MIT license at your discretion, that can be found in the LICENSE-APACHE
 * or LICENSE-MIT files respectively.
 */
package kage.kage.format

import com.google.common.truth.Truth.assertThat
import java.io.ByteArrayInputStream
import kage.crypto.scrypt.ScryptRecipient
import kage.format.AgeFile
import org.bouncycastle.util.encoders.Base64
import org.junit.jupiter.api.Test

class AgeFileTest {

  @Test
  fun testParseAgeGoFile() {
    val testFile =
      Base64.decode(
        "YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IHNjcnlwdCArNlZtcm5hOWRXdjZTNEFBOFJ2MEZRIDE4CjJISTM0aTYxRHNkVHNMdVVvdXoyWk1jVTM1WUk0R2F1TlJEMDBnL0M2Nk0KLS0tIC9GSXA0eElxS1BqUG80aEJkK2lPNDRibyt1R093Q2IvWVZrTTRxcFJhZk0KUuBcu00b/uzC+wlTRwEHxBI4tR1LlkR5YQ7rvOZXJepwOZ7j9pJNIW3jgbIotYnurGE/6A=="
      )

    val inputStream = ByteArrayInputStream(testFile)

    val ageFile = AgeFile.parse(inputStream)

    val recipient = ageFile.header.recipients.first()

    assertThat(recipient.type).isEqualTo(ScryptRecipient.SCRYPT_STANZA_TYPE)
    assertThat(recipient.args).contains(ScryptRecipient.DEFAULT_WORK_FACTOR.toString())
    assertThat(ageFile.body)
      .asList()
      .containsExactlyElementsIn(testFile.takeLast(ageFile.body.size))
  }
}
