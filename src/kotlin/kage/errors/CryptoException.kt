/**
 * Copyright 2022 The kage Authors. All rights reserved. Use of this source code is governed by
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

/** Raised when an error occurs when unwrapping an scrypt stanza from an [kage.Identity]. */
public class ScryptIdentityException(
  message: String? = null,
  cause: Throwable? = null,
) : CryptoException(message, cause)

/** Raised when an error occurs when unwrapping a X25519 stanza from an [kage.Identity]. */
public class X25519IdentityException(
  message: String? = null,
  cause: Throwable? = null,
) : CryptoException(message, cause)

/**
 * Raised when an error occurs while calculating the X25519 shared secret. If the X25519 share is a
 * low order point, the shared secret is the disallowed all-zero value.
 */
public class X25519LowOrderPointException(
  message: String? = null,
  cause: Throwable? = null,
) : CryptoException(message, cause)

/** Raised when an incompatible stanza is provided to [kage.Identity.unwrap] */
public class InvalidIdentityException(
  message: String? = null,
  cause: Throwable? = null,
) : CryptoException(message, cause)

/** Raised when there are no [kage.Identity]s when decrypting a ciphertext */
public class NoIdentitiesException(
  message: String? = null,
  cause: Throwable? = null,
) : CryptoException(message, cause)

public class IncorrectCipherTextSizeException(
  cause: Throwable? = null,
) : CryptoException("Incorrect cipher text size", cause)

/**
 * Raised when an identity is not suitable to decrypt a specific recipient block.
 *
 * This is not a fatal exception, kage code should catch this exception and try a different
 * identity, or fail if other identity does not exist
 */
public class IncorrectIdentityException(
  cause: Throwable? = null,
) : CryptoException("incorrect identity for recipient block", cause)

/** Throw when an error occurs while streaming encrypted or decrypted data */
public class StreamException(
  message: String? = null,
  cause: Throwable? = null,
) : CryptoException(message, cause)
