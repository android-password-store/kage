package kage.kage.utils

import kage.errors.CryptoException
import kage.errors.IncorrectCipherTextSizeException
import kage.errors.IncorrectHMACException
import kage.errors.IncorrectIdentityException
import kage.errors.InvalidAgeKeyException
import kage.errors.InvalidArbitraryStringException
import kage.errors.InvalidBase64StringException
import kage.errors.InvalidFooterException
import kage.errors.InvalidHMACException
import kage.errors.InvalidIdentityException
import kage.errors.InvalidRecipientException
import kage.errors.InvalidScryptRecipientException
import kage.errors.InvalidVersionException
import kage.errors.NoIdentitiesException
import kage.errors.NoRecipientsException
import kage.errors.ParseException
import kage.errors.ScryptIdentityException
import kage.errors.StreamException
import kage.errors.X25519IdentityException
import kage.errors.X25519LowOrderPointException
import kage.test.utils.Expect
import kage.test.utils.Expect.HMACFailure
import kage.test.utils.Expect.HeaderFailure
import kage.test.utils.Expect.NoMatch
import kage.test.utils.Expect.PayloadFailure
import org.bouncycastle.crypto.InvalidCipherTextException

private inline fun <reified T : Exception> hasCause(error: Throwable): Boolean {
  var cause = error.cause
  while(cause != null) {
    if (error.cause is T) return true
    cause = cause.cause
  }
  return false
}

fun mapToUpstreamExpect(error: Throwable): Expect {
  if (error is InvalidIdentityException && hasCause<InvalidCipherTextException>(error)) return NoMatch
  if (error is IncorrectHMACException || hasCause<IncorrectHMACException>(error)) return HeaderFailure
  if (error is IncorrectIdentityException) return NoMatch
  if (error is StreamException) return PayloadFailure
  if (error is ParseException) return HeaderFailure
  if (error is CryptoException) return HeaderFailure

  // TODO: Handle cases where we are throwing anything other than CryptoException or ParseException
  // throw IllegalStateException("Only exceptions thrown by kage can be mapped to expect value")
  return HeaderFailure

//  return when (this) {
//    is CryptoException -> {
//      when (this) {
//        is IncorrectCipherTextSizeException -> HeaderFailure
//        is IncorrectIdentityException -> NoMatch
//        is InvalidBase64StringException -> HeaderFailure
//        is InvalidIdentityException -> HeaderFailure
//        is InvalidScryptRecipientException -> HeaderFailure
//        is NoIdentitiesException -> HeaderFailure
//        is NoRecipientsException -> HeaderFailure
//        is ScryptIdentityException -> if (hasCause<InvalidCipherTextException>(this)) NoMatch else HeaderFailure
//        is StreamException -> PayloadFailure
//        is X25519IdentityException -> /*if (hasCause<InvalidCipherTextException>(this)) NoMatch else*/ HeaderFailure
//        is X25519LowOrderPointException -> HeaderFailure
//        is IncorrectHMACException -> HMACFailure
//      }
//    }
//
//    is ParseException -> {
//      when (this) {
//        is InvalidAgeKeyException -> Expect.HeaderFailure
//        is InvalidArbitraryStringException -> Expect.HeaderFailure
//        is InvalidFooterException -> Expect.HeaderFailure
//        is InvalidHMACException -> Expect.HeaderFailure
//        is InvalidRecipientException -> Expect.HeaderFailure
//        is InvalidVersionException -> Expect.HeaderFailure
//      }
//    }
//
//    else -> {
//    }
//  }
}
