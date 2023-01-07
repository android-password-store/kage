/**
 * Copyright 2023 The kage Authors. All rights reserved. Use of this source code is governed by
 * either an Apache 2.0 or MIT license at your discretion, that can be found in the LICENSE-APACHE
 * or LICENSE-MIT files respectively.
 */
package kage.kage.utils

import kage.errors.CryptoException
import kage.errors.IncorrectHMACException
import kage.errors.IncorrectIdentityException
import kage.errors.InvalidIdentityException
import kage.errors.ParseException
import kage.errors.StreamException
import kage.test.utils.Expect
import kage.test.utils.Expect.HeaderFailure
import kage.test.utils.Expect.NoMatch
import kage.test.utils.Expect.PayloadFailure
import org.bouncycastle.crypto.InvalidCipherTextException

private inline fun <reified T : Exception> hasCause(error: Throwable): Boolean {
  var cause = error.cause
  while (cause != null) {
    if (error.cause is T) return true
    cause = cause.cause
  }
  return false
}

fun mapToUpstreamExpect(error: Throwable): Expect {
  if (error is InvalidIdentityException && hasCause<InvalidCipherTextException>(error))
    return NoMatch
  if (error is IncorrectHMACException || hasCause<IncorrectHMACException>(error))
    return HeaderFailure
  if (error is IncorrectIdentityException) return NoMatch
  if (error is StreamException) return PayloadFailure
  if (error is ParseException) return HeaderFailure
  if (error is CryptoException) return HeaderFailure

  // TODO: Handle cases where we are throwing anything other than CryptoException or ParseException
  //  throw IllegalStateException("Only exceptions thrown by kage can be mapped to expect value")
  return HeaderFailure
}
