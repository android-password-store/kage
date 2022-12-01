/**
 * Copyright 2022 The kage Authors. All rights reserved. Use of this source code is governed by
 * either an Apache 2.0 or MIT license at your discretion, that can be found in the LICENSE-APACHE
 * or LICENSE-MIT files respectively.
 */
package kage.kage.format

import com.github.michaelbull.result.getOrThrow
import com.github.michaelbull.result.unwrapError
import kage.errors.Bech32Exception
import kage.format.Bech32
import kotlin.test.assertEquals
import kotlin.test.assertIs
import org.bouncycastle.util.encoders.Hex
import org.junit.Test

class Bech32Test {

  @Test
  fun testEncode() {
    val s = "age1z2fw2ks7jp7ak3tjven6kxd53m7lxgmn9j7nrt0gfmewcr4sav9sp2n34j"

    val h = "1292e55a1e907ddb45726667ab19b48efdf323732cbd31ade84ef2ec0eb0eb0b"

    val dh = Hex.decode(h)

    val encoded = Bech32.encode("age", dh).getOrThrow()

    assertEquals(s, encoded)
  }

  @Test
  fun testDecode() {
    val s = "age1z2fw2ks7jp7ak3tjven6kxd53m7lxgmn9j7nrt0gfmewcr4sav9sp2n34j"

    val (hrp, data) = Bech32.decode(s).getOrThrow()

    assertEquals("age", hrp)
    assertEquals(
      "1292e55a1e907ddb45726667ab19b48efdf323732cbd31ade84ef2ec0eb0eb0b",
      Hex.toHexString(data)
    )
  }

  // Test used by age.go
  @Test
  fun testBech32() {
    data class T(val string: String, val valid: Boolean)

    val tests =
      listOf(
        T("A12UEL5L", true),
        T("a12uel5l", true),
        T(
          "an83characterlonghumanreadablepartthatcontainsthenumber1andtheexcludedcharactersbio1tt5tgs",
          true
        ),
        T("abcdef1qpzry9x8gf2tvdw0s3jn54khce6mua7lmqqqxw", true),
        T(
          "11qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqc8247j",
          true
        ),
        T("split1checkupstagehandshakeupstreamerranterredcaperred2y9e3w", true),

        // invalid checksum
        T("split1checkupstagehandshakeupstreamerranterredcaperred2y9e2w", false),
        // invalid character (space) in hrp
        T("s lit1checkupstagehandshakeupstreamerranterredcaperredp8hs2p", false),
        T("split1cheo2y9e2w", false), // invalid character (o) in data part
        T("split1a2y9w", false), // too short data part
        T("1checkupstagehandshakeupstreamerranterredcaperred2y9e3w", false), // empty hrp
        // invalid character (DEL) in hrp
        T(
          "spl" + (127).toChar() + "t1checkupstagehandshakeupstreamerranterredcaperred2y9e3w",
          false
        ),
        // too long
        T(
          "11qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqsqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqc8247j",
          false
        ),

        // BIP 173 invalid vectors.
        T(
          "an84characterslonghumanreadablepartthatcontainsthenumber1andtheexcludedcharactersbio1569pvx",
          false
        ),
        T("pzry9x0s0muk", false),
        T("1pzry9x0s0muk", false),
        T("x1b4n0q5v", false),
        T("li1dgmt3", false),
        T("de1lg7wt\\xff", false),
        T("A1G7SGD8", false),
        T("10a06t8", false),
        T("1qzzfhee", false),
      )

    for (test in tests) {
      val str = test.string

      if (!test.valid) {
        val err = Bech32.decode(str)
        assertIs<Bech32Exception>(err.unwrapError())

        continue
      }

      // Valid string decoding should result in no error.
      val (hrp, decoded) = Bech32.decode(str).getOrThrow()

      // Check that it encodes to the same string.
      val encoded = Bech32.encode(hrp, decoded).getOrThrow()

      assertEquals(str, encoded)

      // Flip a bit in the string and make sure it is caught.
      val pos = str.lastIndexOf("1")
      val flipped =
        str.slice(0 until pos + 1) +
          (str[pos + 1].code xor 1).toString() +
          str.slice(pos + 2 until str.length)

      val res = Bech32.decode(flipped)

      assertIs<Bech32Exception>(res.unwrapError())
    }
  }
}
