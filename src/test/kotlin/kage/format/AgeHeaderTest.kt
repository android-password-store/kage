/**
 * Copyright 2021-2022 The kage Authors. All rights reserved. Use of this source code is governed by
 * either an Apache 2.0 or MIT license at your discretion, that can be found in the LICENSE-APACHE
 * or LICENSE-MIT files respectively.
 */
package kage.format

import com.google.common.truth.Truth.assertThat
import java.io.ByteArrayOutputStream
import java.util.Base64
import kage.errors.InvalidFooterException
import kage.errors.InvalidHMACException
import kage.errors.InvalidRecipientException
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows

class AgeHeaderTest {

  @Test
  fun testCompleteHeader() {
    val headerString =
      """age-encryption.org/v1
            |-> X25519 SVrzdFfkPxf0LPHOUGB1gNb9E5Vr8EUDa9kxk04iQ0o
            |0OrTkKHpE7klNLd0k+9Uam5hkQkzMxaqKcIPRIO1sNE
            |-> X25519 8hWaIUmk67IuRZ41zMk2V9f/w3f5qUnXLL7MGPA+zE8
            |tXgpAxKgqyu1jl9I/ATwFgV42ZbNgeAlvCTJ0WgvfEo
            |--- gxhoSa5BciRDt8lOpYNcx4EYtKpS0CJ06F3ZwN82VaM
            |"""
        .trimMargin()

    val reader = headerString.byteInputStream().buffered()
    val header = AgeHeader.parse(reader)
    val actualMac = Base64.getDecoder().decode("gxhoSa5BciRDt8lOpYNcx4EYtKpS0CJ06F3ZwN82VaM")

    assertThat(header.recipients).hasSize(2)
    assertThat(header.mac).asList().containsExactlyElementsIn(actualMac.asList())
  }

  @Test
  fun testVersionLine() {
    val versionLine = "age-encryption.org/v1"

    val reader = versionLine.byteInputStream().buffered()
    AgeHeader.parseVersion(reader)
  }

  @Test
  fun testFooter() {
    val footerLine = "--- gxhoSa5BciRDt8lOpYNcx4EYtKpS0CJ06F3ZwN82VaM"

    val reader = footerLine.byteInputStream().buffered()

    val mac = AgeHeader.parseFooter(reader)
    val actualMac = Base64.getDecoder().decode("gxhoSa5BciRDt8lOpYNcx4EYtKpS0CJ06F3ZwN82VaM")

    assertThat(mac).asList().containsExactlyElementsIn(actualMac.asList())
  }

  @Test
  fun testFooterWithoutMac() {
    val footerLine = "--- "

    val reader = footerLine.byteInputStream().buffered()

    assertThrows<InvalidFooterException> { AgeHeader.parseFooter(reader).decodeToString() }
  }

  @Test
  fun testEmptyFooter() {
    val footerLine = ""

    val reader = footerLine.byteInputStream().buffered()

    assertThrows<InvalidFooterException> { AgeHeader.parseFooter(reader).decodeToString() }
  }

  @Test
  fun testEquality() {
    val headerString =
      """age-encryption.org/v1
            |-> X25519 SVrzdFfkPxf0LPHOUGB1gNb9E5Vr8EUDa9kxk04iQ0o
            |0OrTkKHpE7klNLd0k+9Uam5hkQkzMxaqKcIPRIO1sNE
            |-> X25519 8hWaIUmk67IuRZ41zMk2V9f/w3f5qUnXLL7MGPA+zE8
            |tXgpAxKgqyu1jl9I/ATwFgV42ZbNgeAlvCTJ0WgvfEo
            |--- gxhoSa5BciRDt8lOpYNcx4EYtKpS0CJ06F3ZwN82VaM
            |"""
        .trimMargin()
    val header1 = AgeHeader.parse(headerString.byteInputStream().buffered())
    val header2 = AgeHeader.parse(headerString.byteInputStream().buffered())
    assertThat(header1).isEqualTo(header2)
    assertThat(header1.hashCode()).isEqualTo(header2.hashCode())
  }

  @Test
  fun testMultipleRecipients() {
    val recipients =
      """-> X25519 SVrzdFfkPxf0LPHOUGB1gNb9E5Vr8EUDa9kxk04iQ0o
            |0OrTkKHpE7klNLd0k+9Uam5hkQkzMxaqKcIPRIO1sNE
            |-> X25519 8hWaIUmk67IuRZ41zMk2V9f/w3f5qUnXLL7MGPA+zE8
            |tXgpAxKgqyu1jl9I/ATwFgV42ZbNgeAlvCTJ0WgvfEo
            |-> scrypt GixTkc7+InSPLzPNGU6cFw 18
            |kC4zjzi7LRutdBfOlGHCgox8SXgfYxRYhWM1qPs0ca8
            |-> ssh-rsa SkdmSg
            |SW+xNSybDWTCkWx20FnCcxlfGC889s2hRxT8+giPH2DQMMFV6DyZpveqXtNwI3ts
            |5rVkW/7hCBSqEPQwabC6O5ls75uNjeSURwHAaIwtQ6riL9arjVpHMl8O7GWSRnx3
            |NltQt08ZpBAUkBqq5JKAr20t46ZinEIsD1LsDa2EnJrn0t8Truo2beGwZGkwkE2Y
            |j8mC2GaqR0gUcpGwIk6QZMxOdxNSOO7jhIC32nt1w2Ep1ftk9wV1sFyQo+YYrzOx
            |yCDdUwQAu9oM3Ez6AWkmFyG6AvKIny8I4xgJcBt1DEYZcD5PIAt51nRJQcs2/ANP
            |+Y1rKeTsskMHnlRpOnMlXqoeN6A3xS+EWxFTyg1GREQeaVztuhaL6DVBB22sLskw
            |XBHq/XlkLWkqoLrQtNOPvLoDO80TKUORVsP1y7OyUPHqUumxj9Mn/QtsZjNCPyKN
            |ds7P2OLD/Jxq1o1ckzG3uzv8Vb6sqYUPmRvlXyD7/s/FURA1GetBiQEdRM34xbrB
            |
            |-> ssh-ed25519 Xyg06A rH24zuz7XHFc1lRyQmMrekpLrcKrJupohEh/YjvQCxs
            |Bbtnl6veSZhZmG7uXGQUX0hJbrC8mxDkL3zW06tqlWY
            |---"""
        .trimMargin()

    val reader = recipients.byteInputStream().buffered()
    val parsedRecipients = AgeHeader.parseRecipients(reader)

    assertThat(parsedRecipients).hasSize(5)
  }

  @Test
  fun testReaderPositionAfterParsingRecipients() {
    val recipients =
      """-> X25519 SVrzdFfkPxf0LPHOUGB1gNb9E5Vr8EUDa9kxk04iQ0o
            |0OrTkKHpE7klNLd0k+9Uam5hkQkzMxaqKcIPRIO1sNE
            |-> X25519 8hWaIUmk67IuRZ41zMk2V9f/w3f5qUnXLL7MGPA+zE8
            |tXgpAxKgqyu1jl9I/ATwFgV42ZbNgeAlvCTJ0WgvfEo
            |---"""
        .trimMargin()

    val reader = recipients.byteInputStream().buffered()
    val charArray = ByteArray(3)
    AgeHeader.parseRecipients(reader)

    reader.read(charArray)
    val line = charArray.decodeToString()

    assertThat(line).startsWith("---")
  }

  @Test
  fun testWriteAgeHeaderWithoutMac() {
    val header =
      """age-encryption.org/v1
            |-> X25519 SVrzdFfkPxf0LPHOUGB1gNb9E5Vr8EUDa9kxk04iQ0o
            |0OrTkKHpE7klNLd0k+9Uam5hkQkzMxaqKcIPRIO1sNE
            |-> X25519 8hWaIUmk67IuRZ41zMk2V9f/w3f5qUnXLL7MGPA+zE8
            |tXgpAxKgqyu1jl9I/ATwFgV42ZbNgeAlvCTJ0WgvfEo
            |--- gxhoSa5BciRDt8lOpYNcx4EYtKpS0CJ06F3ZwN82VaM
            |"""
        .trimMargin()

    val reader = header.byteInputStream().buffered()
    val ageHeader = AgeHeader.parse(reader)

    val outputStream = ByteArrayOutputStream()
    outputStream.bufferedWriter().use { writer -> ageHeader.write(writer) }
    val output = outputStream.toByteArray().decodeToString()

    assertThat(output).isEqualTo(header)
  }

  @Test
  fun testEmptyReader() {
    val header =
      """
      |age-encryption.org/v1
    """
        .trimMargin()

    assertThrows<InvalidRecipientException> { AgeHeader.parse(header.byteInputStream().buffered()) }
  }

  @Test
  fun testEmptyMac() {
    val header = AgeHeader(emptyList(), ByteArray(0))
    assertThrows<InvalidHMACException> { header.write(ByteArrayOutputStream().bufferedWriter()) }
  }
}
