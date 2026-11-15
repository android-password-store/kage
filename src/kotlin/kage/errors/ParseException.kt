/**
 * Copyright 2021-2022 The kage Authors. All rights reserved. Use of this source code is governed by
 * either an Apache 2.0 or MIT license at your discretion, that can be found in the LICENSE-APACHE
 * or LICENSE-MIT files respectively.
 */
package kage.errors

/**
 * Signals an error while parsing age-formatted structures, such as [kage.format.AgeHeader].
 *
 * Other parsed structures include [kage.format.AgeKeyFile] and [kage.format.AgeStanza].
 *
 * @param message detail about the parsing error
 * @param cause underlying error
 */
public sealed class ParseException
@JvmOverloads
constructor(message: String? = null, cause: Throwable? = null) : Exception(message, cause)

/**
 * Signals a disallowed string while parsing an [kage.format.AgeHeader].
 *
 * For example, the string may contain non-ASCII characters.
 *
 * @param message detail about the parsing error
 * @param cause underlying error
 */
public class InvalidArbitraryStringException
@JvmOverloads
constructor(message: String? = null, cause: Throwable? = null) : ParseException(message, cause)

/**
 * Signals a version that does not match the expected version.
 *
 * @param message detail about the parsing error
 * @param cause underlying error
 */
public class InvalidVersionException
@JvmOverloads
constructor(message: String? = null, cause: Throwable? = null) : ParseException(message, cause)

/**
 * Signals an error while parsing [kage.format.AgeStanza] for [kage.Recipient]s.
 *
 * @param message detail about the parsing error
 * @param cause underlying error
 */
public class InvalidRecipientException
@JvmOverloads
constructor(message: String? = null, cause: Throwable? = null) : ParseException(message, cause)

/**
 * Signals an invalid footer for an [kage.format.AgeHeader].
 *
 * @param message detail about the parsing error
 * @param cause underlying error
 */
public class InvalidFooterException
@JvmOverloads
constructor(message: String? = null, cause: Throwable? = null) : ParseException(message, cause)

/**
 * Signals an empty MAC while writing an [kage.format.AgeHeader].
 *
 * @param message detail about the parsing error
 * @param cause underlying error
 */
public class InvalidHMACException
@JvmOverloads
constructor(message: String? = null, cause: Throwable? = null) : ParseException(message, cause)

/**
 * Signals an empty private key while parsing an [kage.format.AgeKeyFile].
 *
 * @param message detail about the parsing error
 * @param cause underlying error
 */
public class InvalidAgeKeyException
@JvmOverloads
constructor(message: String? = null, cause: Throwable? = null) : ParseException(message, cause)

/**
 * Signals a missing or truncated payload nonce after the header.
 *
 * age reads the nonce as the final step of header processing, so it treats a missing nonce as a
 * header failure rather than a payload failure.
 *
 * @param message detail about the parsing error
 * @param cause underlying error
 */
public class InvalidNonceException
@JvmOverloads
constructor(message: String? = null, cause: Throwable? = null) : ParseException(message, cause)

/**
 * Signals an unrecognized line or empty file in [kage.Age.parseIdentities].
 *
 * @param message detail about the parsing error
 * @param cause underlying error
 */
public class InvalidIdentityFileException
@JvmOverloads
constructor(message: String? = null, cause: Throwable? = null) : ParseException(message, cause)

/**
 * Signals an unrecognized line or empty file in [kage.Age.parseRecipients].
 *
 * @param message detail about the parsing error
 * @param cause underlying error
 */
public class InvalidRecipientFileException
@JvmOverloads
constructor(message: String? = null, cause: Throwable? = null) : ParseException(message, cause)
