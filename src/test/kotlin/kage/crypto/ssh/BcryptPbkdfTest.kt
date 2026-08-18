/**
 * Copyright 2022 The kage Authors. All rights reserved. Use of this source code is governed by
 * either an Apache 2.0 or MIT license at your discretion, that can be found in the LICENSE-APACHE
 * or LICENSE-MIT files respectively.
 */
package kage.kage.crypto.ssh

import com.google.common.truth.Truth.assertThat
import kage.crypto.ssh.BcryptPbkdf
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows

// Known-answer vectors extracted verbatim from OpenBSD's own bcrypt_pbkdf_test.c, including its
// embedded-NUL-byte and length-truncation cases.
class BcryptPbkdfTest {
  private data class Vector(
    val rounds: Int,
    val passwordHex: String,
    val saltHex: String,
    val keyHex: String,
  )

  private val vectors =
    listOf(
      Vector(
        4,
        "70617373776f7264",
        "73616c74",
        "5bbf0cc293587f1c3635555c27796598d47e579071bf427e9d8fbe842aba34d9",
      ),
      Vector(4, "70617373776f7264", "00", "c12b566235eee04c212598970a579a67"),
      Vector(4, "00", "73616c74", "6051be18c2f4f82cbf0efee5471b4bb9"),
      Vector(
        4,
        "70617373776f726400",
        "73616c7400",
        "7410e44cf4fa07bfaac8a928b1727fac001375e7bf7384370f48efd121743050",
      ),
      Vector(4, "7061737300776f72", "7361006c", "c2bffd9db38f6569efef4372f4de83c0"),
      Vector(4, "7061737300776f7264", "7361006c74", "4ba4ac3925c0e8d7f0cdb6bb1684a56f"),
      Vector(
        8,
        "70617373776f7264",
        "73616c74",
        "e1367ec5151a33faac4cc1c144cd23fa15d5548493ecc99b9b5d9c0d3b27bec76227ea66088b849b20ab7aa478010246e74bba51723fefa9f9474d6508845e8d",
      ),
      Vector(42, "70617373776f7264", "73616c74", "833cf0dcf56db65608e8f0dc0ce882bd"),
      Vector(
        8,
        "4c6f72656d20697073756d20646f6c6f722073697420616d65742c20636f6e7365637465747572206164697069736963696e6720656c69742c2073656420646f20656975736d6f642074656d706f7220696e6369646964756e74207574206c61626f726520657420646f6c6f7265206d61676e6120616c697175612e20557420656e696d206164206d696e696d2076656e69616d2c2071756973206e6f737472756420657865726369746174696f6e20756c6c616d636f206c61626f726973206e69736920757420616c697175697020657820656120636f6d6d6f646f20636f6e7365717561742e2044756973206175746520697275726520646f6c6f7220696e20726570726568656e646572697420696e20766f6c7570746174652076656c697420657373652063696c6c756d20646f6c6f726520657520667567696174206e756c6c612070617269617475722e204578636570746575722073696e74206f6363616563617420637570696461746174206e6f6e2070726f6964656e742c2073756e7420696e2063756c706120717569206f666669636961206465736572756e74206d6f6c6c697420616e696d20696420657374206c61626f72756d2e",
        "73616c697300",
        "10978b07253df57f71a162eb0e8ad30a",
      ),
      Vector(
        8,
        "0db3ac94b3ee53284f4a22893b3c24ae",
        "3a62f0f0dbcef823cfcc854856ea1028",
        "204438175eee7ce136c91b49a67923ff",
      ),
      Vector(
        8,
        "0db3ac94b3ee53284f4a22893b3c24ae",
        "3a62f0f0dbcef823cfcc854856ea1028",
        "2054b9fff34e3721440334746828e9ed38de4b72e0a69adc170a13b5e8d646385ea4034ae6d26600ee2332c5ed40ad557c86e3403fbb30e4e1dc1ae06b99a071368f518d2c426651c9e7e437fd6c915b1bbfc3a4cea71491490ea7afb7dd0290a678a4f441128db1792eab2776b21eb4238e0715add4127dff44e4b3e4cc4c4f9970083f3f74bd698873fdf648844f75c9bf7f9e0c4d9e5d89a7783997492966616707611cb901de31a19726b6e08c3a8001661f2d5c9dcc33b4aa072f90dd0b3f548d5eeba4211397e2fb062e526e1d68f46a4ce256185b4badc2685fbe78e1c7657b59f83ab9ab80cf9318d6add1f5933f12d6f36182c8e8115f68030a1244",
      ),
    )

  @Test
  fun derive_matchesOpenBsdKnownAnswerVectors() {
    for (v in vectors) {
      val expected = hexToBytes(v.keyHex)
      val actual =
        BcryptPbkdf.derive(
          hexToBytes(v.passwordHex),
          hexToBytes(v.saltHex),
          expected.size,
          v.rounds,
        )
      assertThat(actual).isEqualTo(expected)
    }
  }

  @Test
  fun derive_doesNotOverwriteBeyondRequestedLength() {
    // Same case the C test suite checks explicitly before running the table above: deriving 88
    // bytes must not touch byte 88 onward of a larger buffer.
    val key = ByteArray(96)
    val derived = BcryptPbkdf.derive("password".toByteArray(), "salt".toByteArray(), 88, 4)
    System.arraycopy(derived, 0, key, 0, derived.size)
    assertThat(key[88]).isEqualTo(0.toByte())
    assertThat(key[89]).isEqualTo(0.toByte())
    assertThat(key[90]).isEqualTo(0.toByte())
  }

  @Test
  fun derive_rejectsEmptyPasswordSaltOrZeroRounds() {
    assertThrows<IllegalArgumentException> {
      BcryptPbkdf.derive(ByteArray(0), "salt".toByteArray(), 16, 4)
    }
    assertThrows<IllegalArgumentException> {
      BcryptPbkdf.derive("password".toByteArray(), ByteArray(0), 16, 4)
    }
    assertThrows<IllegalArgumentException> {
      BcryptPbkdf.derive("password".toByteArray(), "salt".toByteArray(), 16, 0)
    }
  }

  private fun hexToBytes(hex: String): ByteArray =
    ByteArray(hex.length / 2) { hex.substring(it * 2, it * 2 + 2).toInt(16).toByte() }
}
