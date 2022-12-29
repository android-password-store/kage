/**
 * Copyright 2021-2022 The kage Authors. All rights reserved. Use of this source code is governed by
 * either an Apache 2.0 or MIT license at your discretion, that can be found in the LICENSE-APACHE
 * or LICENSE-MIT files respectively.
 */
package kage.errors

/** Wrapper type for errors triggered while parsing an [kage.format.AgeStanza] */
public sealed class ParseException(
  message: String? = null,
  cause: Throwable? = null,
) : Exception(message, cause)

/** Raised when a non-ASCII string is encountered when parsing an [kage.format.AgeHeader]. */
public class InvalidArbitraryStringException(
  message: String? = null,
  cause: Throwable? = null,
) : ParseException(message, cause)

/** Raised when the parsed version is not an expected one. */
public class InvalidVersionException(
  message: String? = null,
  cause: Throwable? = null,
) : ParseException(message, cause)

/** Raised when a failure occurs while parsing [kage.format.AgeStanza] for [kage.Recipient]s. */
public class InvalidRecipientException(
  message: String? = null,
  cause: Throwable? = null,
) : ParseException(message, cause)

/** Raised when the footer for a [kage.format.AgeHeader] is incorrect. */
public class InvalidFooterException(
  message: String? = null,
  cause: Throwable? = null,
) : ParseException(message, cause)

/** Raised when the [kage.format.AgeHeader.mac] is empty when writing a [kage.format.AgeHeader]. */
public class InvalidHMACException(
  message: String? = null,
  cause: Throwable? = null,
) : ParseException(message, cause)

/**
 * Raised when the [kage.format.AgeKeyFile.privateKey] is empty when parsing a
 * [kage.format.AgeKeyFile].
 */
public class InvalidAgeKeyException(
  message: String? = null,
  cause: Throwable? = null,
) : ParseException(message, cause)

/** Raised when the Base64 string is not canonical according to RFC 4648 section 3.5 */
public class InvalidBase64StringException(
  message: String? = null,
  cause: Throwable? = null,
) : ParseException(message, cause)
