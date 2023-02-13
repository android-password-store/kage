/**
 * Copyright 2022 The kage Authors. All rights reserved. Use of this source code is governed by
 * either an Apache 2.0 or MIT license at your discretion, that can be found in the LICENSE-APACHE
 * or LICENSE-MIT files respectively.
 */
package kage

import com.github.michaelbull.result.getError
import com.github.michaelbull.result.runCatching
import com.google.common.truth.Truth.assertThat
import java.io.ByteArrayOutputStream
import java.nio.file.Files
import java.nio.file.Paths
import java.security.MessageDigest
import kage.kage.test.utils.TestSuite
import kage.kage.utils.mapToUpstreamExpect
import kage.test.utils.Expect.Success
import kage.test.utils.PayloadHash
import kotlin.io.path.name
import org.junit.jupiter.api.DynamicTest
import org.junit.jupiter.api.TestFactory
import org.junit.jupiter.api.fail

class UpstreamTestSuite {
  private val testFixtureRoot = Paths.get("src", "test", "resources", "CCTV", "age", "testdata")

  @TestFactory
  fun generateTests(): List<DynamicTest> {
    return Files.newDirectoryStream(testFixtureRoot)
      // TODO: enable armor tests
      .filter { path -> !path.name.contains("armor") }
      .map { path ->
        val contents = path.toFile().readBytes()
        DynamicTest.dynamicTest(path.name) {
          val suite = TestSuite.parse(contents)
          val expect = suite.expect

          val baos = ByteArrayOutputStream()
          val result = runCatching {
            Age.decryptStream(suite.identities, suite.testContent.inputStream(), baos)
          }

          val error = result.getError()
          if (error == null) {
            if (expect != Success) fail("expected $expect, got success")
            suite.payloadHash?.let { expectedHash ->
              val md = MessageDigest.getInstance("SHA-256")
              val payloadHash = PayloadHash(md.digest(baos.toByteArray()))
              assertThat(payloadHash.bytes).isEqualTo(expectedHash.bytes)
            }
          } else {
            error.printStackTrace()
            val actual = mapToUpstreamExpect(error)
            assertThat(actual).isEqualTo(expect)
          }
        }
      }
  }
}
