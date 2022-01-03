/**
 * Copyright 2021 The kage Authors. All rights reserved. Use of this source code is governed by
 * either an Apache 2.0 or MIT license at your discretion, that can be found in the LICENSE-APACHE
 * or LICENSE-MIT files respectively.
 */
package kage.errors

/** Wrapper class for errors raised during a cryptographic operation. */
public sealed class CryptoException(
  message: String? = null,
  cause: Throwable? = null,
) : Exception(message, cause)

/** Raised when no [kage.Recipient] is available in the ciphertext. */
public class NoRecipientsException(
  message: String? = null,
  cause: Throwable? = null,
) : CryptoException(message, cause)

/**
 * Raised when there are more than one [kage.Recipient]s and one is an
 * [kage.crypto.scrypt.ScryptRecipient]. This is a specially cased situation from the spec which
 * requires that there only be one [kage.Recipient] if it is a [kage.crypto.scrypt.ScryptRecipient].
 */
public class InvalidScryptRecipientException(
  message: String? = null,
  cause: Throwable? = null,
) : CryptoException(message, cause)
