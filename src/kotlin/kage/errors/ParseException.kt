/**
 * Copyright 2021-2022 The kage Authors. All rights reserved. Use of this source code is governed by
 * either an Apache 2.0 or MIT license at your discretion, that can be found in the LICENSE-APACHE
 * or LICENSE-MIT files respectively.
 */
package kage.errors

/**
 * Wrapper type for errors triggered while parsing age-formatted structures (for example,
 * [kage.format.AgeHeader], [kage.format.AgeKeyFile], and [kage.format.AgeStanza]).
 */
public sealed class ParseException
@JvmOverloads
constructor(message: String? = null, cause: Throwable? = null) : Exception(message, cause)

/**
 * Raised when an invalid arbitrary string is encountered when parsing an [kage.format.AgeHeader],
 * such as one containing disallowed non-ASCII characters.
 */
public class InvalidArbitraryStringException
@JvmOverloads
constructor(message: String? = null, cause: Throwable? = null) : ParseException(message, cause)

/** Raised when the parsed version is not an expected one. */
public class InvalidVersionException
@JvmOverloads
constructor(message: String? = null, cause: Throwable? = null) : ParseException(message, cause)

/** Raised when a failure occurs while parsing [kage.format.AgeStanza] for [kage.Recipient]s. */
public class InvalidRecipientException
@JvmOverloads
constructor(message: String? = null, cause: Throwable? = null) : ParseException(message, cause)

/** Raised when the footer for a [kage.format.AgeHeader] is incorrect. */
public class InvalidFooterException
@JvmOverloads
constructor(message: String? = null, cause: Throwable? = null) : ParseException(message, cause)

/** Raised when the [kage.format.AgeHeader.mac] is empty when writing a [kage.format.AgeHeader]. */
public class InvalidHMACException
@JvmOverloads
constructor(message: String? = null, cause: Throwable? = null) : ParseException(message, cause)

/**
 * Raised when the [kage.format.AgeKeyFile.privateKey] is empty when parsing a
 * [kage.format.AgeKeyFile].
 */
public class InvalidAgeKeyException
@JvmOverloads
constructor(message: String? = null, cause: Throwable? = null) : ParseException(message, cause)

/**
 * Raised when the payload nonce cannot be read after the header. age reads the nonce as the final
 * step of header processing, so a missing or truncated nonce is treated as a header failure rather
 * than a payload failure.
 */
public class InvalidNonceException
@JvmOverloads
constructor(message: String? = null, cause: Throwable? = null) : ParseException(message, cause)
