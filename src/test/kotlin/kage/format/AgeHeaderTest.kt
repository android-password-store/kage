package kage.format

import java.io.ByteArrayOutputStream
import java.util.Base64
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

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
            |""".trimMargin()

    val reader = headerString.reader().buffered()
    val header = AgeHeader.parse(reader)
    val actualMac = Base64.getDecoder().decode("gxhoSa5BciRDt8lOpYNcx4EYtKpS0CJ06F3ZwN82VaM")

    assertEquals(header.recipients.size, 2)
    assertEquals(header.mac.decodeToString(), actualMac.decodeToString())
  }

  @Test
  fun testVersionLine() {
    val versionLine = "age-encryption.org/v1"

    val reader = versionLine.reader().buffered()
    AgeHeader.parseVersion(reader)
  }

  @Test
  fun testFooter() {
    val footerLine = "--- gxhoSa5BciRDt8lOpYNcx4EYtKpS0CJ06F3ZwN82VaM"

    val reader = footerLine.reader().buffered()

    val mac = AgeHeader.parseFooter(reader).decodeToString()
    val actualMac =
      Base64.getDecoder().decode("gxhoSa5BciRDt8lOpYNcx4EYtKpS0CJ06F3ZwN82VaM").decodeToString()

    assertEquals(mac, actualMac)
  }

  @Test
  fun testFooterWithoutMac() {
    val footerLine = "--- "

    val reader = footerLine.reader().buffered()

    assertFailsWith<InvalidFooterException> { AgeHeader.parseFooter(reader).decodeToString() }
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
            |---""".trimMargin()

    val reader = recipients.reader().buffered()
    val parsedRecipients = AgeHeader.parseRecipients(reader)

    assertEquals(parsedRecipients.size, 5)
  }

  @Test
  fun testReaderPositionAfterParsingRecipients() {
    val recipients =
      """-> X25519 SVrzdFfkPxf0LPHOUGB1gNb9E5Vr8EUDa9kxk04iQ0o
            |0OrTkKHpE7klNLd0k+9Uam5hkQkzMxaqKcIPRIO1sNE
            |-> X25519 8hWaIUmk67IuRZ41zMk2V9f/w3f5qUnXLL7MGPA+zE8
            |tXgpAxKgqyu1jl9I/ATwFgV42ZbNgeAlvCTJ0WgvfEo
            |---"""".trimMargin()

    val reader = recipients.reader().buffered()
    val charArray = CharArray(3)
    AgeHeader.parseRecipients(reader)

    reader.read(charArray)
    val line = charArray.concatToString()

    assert(line.startsWith("---"))
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
            |""".trimMargin()

    val reader = header.reader().buffered()
    val ageHeader = AgeHeader.parse(reader)

    val outputStream = ByteArrayOutputStream()
    outputStream.bufferedWriter().use { writer ->
      AgeHeader.write(writer, ageHeader)
    }
    val output = outputStream.toByteArray().decodeToString()

    assertEquals(header, output)
  }
}
