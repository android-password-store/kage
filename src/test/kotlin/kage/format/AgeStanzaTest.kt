/**
 * Copyright 2021-2022 The kage Authors. All rights reserved. Use of this source code is governed by
 * either an Apache 2.0 or MIT license at your discretion, that can be found in the LICENSE-APACHE
 * or LICENSE-MIT files respectively.
 */
package kage.format

import com.google.common.truth.Truth.assertThat
import java.io.ByteArrayOutputStream
import java.util.Base64
import kage.errors.InvalidArbitraryStringException
import kage.errors.InvalidRecipientException
import kage.errors.ParseException
import kage.utils.readLine
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows

class AgeStanzaTest {
  @Test
  fun testRecipientLineWithOnlyType() {
    val recipientLine = "-> X25519"

    val (type, args) = AgeStanza.parseRecipientLine(recipientLine)
    assertThat(type).isEqualTo("X25519")
    assertThat(args).isEmpty()
  }

  @Test
  fun testRecipientLineWithSingleArgument() {
    val recipientLine = "-> X25519 ARG1"

    val (type, args) = AgeStanza.parseRecipientLine(recipientLine)
    assertThat(type).isEqualTo("X25519")
    assertThat(args).containsExactly("ARG1")
  }

  @Test
  fun testRecipientLineWithMultipleArguments() {
    val recipientLine = "-> X25519 ARG1 ARG2"

    val (type, args) = AgeStanza.parseRecipientLine(recipientLine)
    assertThat(type).isEqualTo("X25519")
    assertThat(args).containsExactly("ARG1", "ARG2")
  }

  @Test
  fun testRecipientLineFailsWithExtraSpace() {
    val recipientLine = "-> X25519 "

    assertThrows<ParseException> { AgeStanza.parseRecipientLine(recipientLine) }
  }

  @Test
  fun testRecipientLineFailsWithoutType() {
    val recipientLine = "-> "

    assertThrows<ParseException> { AgeStanza.parseRecipientLine(recipientLine) }
  }

  @Test
  fun testSingleLineBodyIsParsedCorrectly() {
    val stanza =
      """-> X25519 SVrzdFfkPxf0LPHOUGB1gNb9E5Vr8EUDa9kxk04iQ0o
            |0OrTkKHpE7klNLd0k+9Uam5hkQkzMxaqKcIPRIO1sNE
            |"""
        .trimMargin()

    val reader = stanza.byteInputStream().buffered()

    // Read recipient line
    reader.readLine()

    val body = AgeStanza.parseBodyLines(reader)
    val bytes = Base64.getEncoder().withoutPadding().encode(body)
    assertThat(bytes.decodeToString()).isEqualTo("0OrTkKHpE7klNLd0k+9Uam5hkQkzMxaqKcIPRIO1sNE")
  }

  @Test
  fun testMultiLineBodyIsParsedCorrectly() {
    val stanza =
      """-> ssh-rsa SkdmSg
            |SW+xNSybDWTCkWx20FnCcxlfGC889s2hRxT8+giPH2DQMMFV6DyZpveqXtNwI3ts
            |5rVkW/7hCBSqEPQwabC6O5ls75uNjeSURwHAaIwtQ6riL9arjVpHMl8O7GWSRnx3
            |NltQt08ZpBAUkBqq5JKAr20t46ZinEIsD1LsDa2EnJrn0t8Truo2beGwZGkwkE2Y
            |j8mC2GaqR0gUcpGwIk6QZMxOdxNSOO7jhIC32nt1w2Ep1ftk9wV1sFyQo+YYrzOx
            |yCDdUwQAu9oM3Ez6AWkmFyG6AvKIny8I4xgJcBt1DEYZcD5PIAt51nRJQcs2/ANP
            |+Y1rKeTsskMHnlRpOnMlXqoeN6A3xS+EWxFTyg1GREQeaVztuhaL6DVBB22sLskw
            |XBHq/XlkLWkqoLrQtNOPvLoDO80TKUORVsP1y7OyUPHqUumxj9Mn/QtsZjNCPyKN
            |ds7P2OLD/Jxq1o1ckzG3uzv8Vb6sqYUPmRvlXyD7/s/FURA1GetBiQEdRM34xbrB
            |
            |"""
        .trimMargin()

    val base64Body =
      """SW+xNSybDWTCkWx20FnCcxlfGC889s2hRxT8+giPH2DQMMFV6DyZpveqXtNwI3ts
            |5rVkW/7hCBSqEPQwabC6O5ls75uNjeSURwHAaIwtQ6riL9arjVpHMl8O7GWSRnx3
            |NltQt08ZpBAUkBqq5JKAr20t46ZinEIsD1LsDa2EnJrn0t8Truo2beGwZGkwkE2Y
            |j8mC2GaqR0gUcpGwIk6QZMxOdxNSOO7jhIC32nt1w2Ep1ftk9wV1sFyQo+YYrzOx
            |yCDdUwQAu9oM3Ez6AWkmFyG6AvKIny8I4xgJcBt1DEYZcD5PIAt51nRJQcs2/ANP
            |+Y1rKeTsskMHnlRpOnMlXqoeN6A3xS+EWxFTyg1GREQeaVztuhaL6DVBB22sLskw
            |XBHq/XlkLWkqoLrQtNOPvLoDO80TKUORVsP1y7OyUPHqUumxj9Mn/QtsZjNCPyKN
            |ds7P2OLD/Jxq1o1ckzG3uzv8Vb6sqYUPmRvlXyD7/s/FURA1GetBiQEdRM34xbrB
            |"""
        .trimMargin()

    val reader = stanza.byteInputStream().buffered()

    // Read recipient line
    reader.readLine()

    val body = AgeStanza.parseBodyLines(reader)
    val bytes = Base64.getEncoder().withoutPadding().encode(body)
    // The bytes when encoded do not preserve the '\n' character so for the test we are comparing it
    // without the '\n' characters
    // The writer test should cover wrapping the lines at 64 columns.
    assertThat(bytes.decodeToString()).isEqualTo(base64Body.split("\n").joinToString(""))
  }

  @Test
  fun testIncorrectBodyThrowsException() {
    // Here the body does not end on a partial line and hence should throw an error
    val stanza =
      """-> X25519 SVrzdFfkPxf0LPHOUGB1gNb9E5Vr8EUDa9kxk04iQ0o
            |5rVkW/7hCBSqEPQwabC6O5ls75uNjeSURwHAaIwtQ6riL9arjVpHMl8O7GWSRnx3
            |"""
        .trimMargin()

    val reader = stanza.byteInputStream().buffered()

    // Read recipient line
    reader.readLine()

    assertThrows<InvalidRecipientException> { AgeStanza.parseBodyLines(reader) }
  }

  @Test
  fun testArgumentsAreSplitCorrectly() {
    val recipientLine = "-> X25519 ARG1 ARG2"

    val (prefix, args) = ParseUtils.splitArgs(recipientLine)
    assertThat(prefix).isEqualTo("->")
    assertThat(args).containsExactly("X25519", "ARG1", "ARG2")
  }

  @Test
  fun testArbitraryStringFailsIfEmpty() {
    val arbitraryString = ""

    assertThrows<InvalidArbitraryStringException> {
      ParseUtils.isValidArbitraryString(arbitraryString)
    }
  }

  @Test
  fun testArbitraryStringFailsOutsideCharacterRange() {
    val charCode32String = Char(32).toString() // SPACE
    val charCode127String = Char(127).toString() // DEL

    // Here we're checking both limits individually to make sure both are correct
    val code32Result = ParseUtils.isValidArbitraryString(charCode32String)
    assertThat(code32Result).isFalse()

    val code127Result = ParseUtils.isValidArbitraryString(charCode127String)
    assertThat(code127Result).isFalse()
  }

  @Test
  fun testArbitraryStringInCharacterRange() {
    val arbitraryString = Char(33).toString() + Char(100) + Char(126)

    // Here we don't need to check limits individually since any error will change the result to
    // false
    val result = ParseUtils.isValidArbitraryString(arbitraryString)
    assertThat(result).isTrue()
  }

  @Test
  fun testWriteSingleLineBody() {
    val stanza =
      """-> X25519 SVrzdFfkPxf0LPHOUGB1gNb9E5Vr8EUDa9kxk04iQ0o
            |0OrTkKHpE7klNLd0k+9Uam5hkQkzMxaqKcIPRIO1sNE
            |"""
        .trimMargin()

    val actualBody =
      """0OrTkKHpE7klNLd0k+9Uam5hkQkzMxaqKcIPRIO1sNE
        |"""
        .trimMargin()

    val reader = stanza.byteInputStream().buffered()
    val ageStanza = AgeStanza.parse(reader)

    val outputStream = ByteArrayOutputStream()
    outputStream.bufferedWriter().use { writer -> AgeStanza.writeBody(writer, ageStanza.body) }
    val output = outputStream.toByteArray().decodeToString()

    assertThat(output).isEqualTo(actualBody)
  }

  @Test
  fun testWriteMultiLineBody() {
    val stanza =
      """-> ssh-rsa SkdmSg
            |SW+xNSybDWTCkWx20FnCcxlfGC889s2hRxT8+giPH2DQMMFV6DyZpveqXtNwI3ts
            |5rVkW/7hCBSqEPQwabC6O5ls75uNjeSURwHAaIwtQ6riL9arjVpHMl8O7GWSRnx3
            |NltQt08ZpBAUkBqq5JKAr20t46ZinEIsD1LsDa2EnJrn0t8Truo2beGwZGkwkE2Y
            |j8mC2GaqR0gUcpGwIk6QZMxOdxNSOO7jhIC32nt1w2Ep1ftk9wV1sFyQo+YYrzOx
            |yCDdUwQAu9oM3Ez6AWkmFyG6AvKIny8I4xgJcBt1DEYZcD5PIAt51nRJQcs2/ANP
            |+Y1rKeTsskMHnlRpOnMlXqoeN6A3xS+EWxFTyg1GREQeaVztuhaL6DVBB22sLskw
            |XBHq/XlkLWkqoLrQtNOPvLoDO80TKUORVsP1y7OyUPHqUumxj9Mn/QtsZjNCPyKN
            |ds7P2OLD/Jxq1o1ckzG3uzv8Vb6sqYUPmRvlXyD7/s/FURA1GetBiQEdRM34xbrB
            |
            |"""
        .trimMargin()

    val actualBody =
      """SW+xNSybDWTCkWx20FnCcxlfGC889s2hRxT8+giPH2DQMMFV6DyZpveqXtNwI3ts
            |5rVkW/7hCBSqEPQwabC6O5ls75uNjeSURwHAaIwtQ6riL9arjVpHMl8O7GWSRnx3
            |NltQt08ZpBAUkBqq5JKAr20t46ZinEIsD1LsDa2EnJrn0t8Truo2beGwZGkwkE2Y
            |j8mC2GaqR0gUcpGwIk6QZMxOdxNSOO7jhIC32nt1w2Ep1ftk9wV1sFyQo+YYrzOx
            |yCDdUwQAu9oM3Ez6AWkmFyG6AvKIny8I4xgJcBt1DEYZcD5PIAt51nRJQcs2/ANP
            |+Y1rKeTsskMHnlRpOnMlXqoeN6A3xS+EWxFTyg1GREQeaVztuhaL6DVBB22sLskw
            |XBHq/XlkLWkqoLrQtNOPvLoDO80TKUORVsP1y7OyUPHqUumxj9Mn/QtsZjNCPyKN
            |ds7P2OLD/Jxq1o1ckzG3uzv8Vb6sqYUPmRvlXyD7/s/FURA1GetBiQEdRM34xbrB
            |
            |"""
        .trimMargin()

    val reader = stanza.byteInputStream().buffered()
    val ageStanza = AgeStanza.parse(reader)

    val outputStream = ByteArrayOutputStream()
    outputStream.bufferedWriter().use { writer -> AgeStanza.writeBody(writer, ageStanza.body) }
    val output = outputStream.toByteArray().decodeToString()

    assertThat(output).isEqualTo(actualBody)
  }

  @Test
  fun testWriteAgeStanza() {
    val stanza =
      """-> X25519 SVrzdFfkPxf0LPHOUGB1gNb9E5Vr8EUDa9kxk04iQ0o
            |0OrTkKHpE7klNLd0k+9Uam5hkQkzMxaqKcIPRIO1sNE
            |"""
        .trimMargin()

    val reader = stanza.byteInputStream().buffered()
    val ageStanza = AgeStanza.parse(reader)

    val outputStream = ByteArrayOutputStream()
    outputStream.bufferedWriter().use { writer -> AgeStanza.write(writer, ageStanza) }
    val output = outputStream.toByteArray().decodeToString()

    assertThat(output).isEqualTo(stanza)
  }

  @Test
  fun testWriteAgeStanzaDoesNotAddExtraSpaceWhenNoArgsArePresent() {
    val stanza =
      """-> X25519
            |0OrTkKHpE7klNLd0k+9Uam5hkQkzMxaqKcIPRIO1sNE
            |"""
        .trimMargin()

    val reader = stanza.byteInputStream().buffered()
    val ageStanza = AgeStanza.parse(reader)

    val outputStream = ByteArrayOutputStream()
    outputStream.bufferedWriter().use { writer -> AgeStanza.write(writer, ageStanza) }
    val output = outputStream.toByteArray().decodeToString()
    val endsWithSpace = output.lines().first().endsWith(" ")

    assertThat(endsWithSpace).isFalse()
    assertThat(output).isEqualTo(stanza)
  }
}
