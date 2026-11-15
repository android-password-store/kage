/**
 * Copyright 2022 The kage Authors. All rights reserved. Use of this source code is governed by
 * either an Apache 2.0 or MIT license at your discretion, that can be found in the LICENSE-APACHE
 * or LICENSE-MIT files respectively.
 */
package kage.errors

/**
 * Signals an error during a cryptographic operation.
 *
 * @param message detail about the error
 * @param cause underlying error
 */
public sealed class CryptoException
@JvmOverloads
constructor(message: String? = null, cause: Throwable? = null) : Exception(message, cause)

/**
 * Signals an encryption request with no [kage.Recipient]s.
 *
 * @param message detail about the error
 * @param cause underlying error
 */
public class NoRecipientsException
@JvmOverloads
constructor(message: String? = null, cause: Throwable? = null) : CryptoException(message, cause)

/**
 * Signals multiple [kage.Recipient]s when one is a [kage.crypto.scrypt.ScryptRecipient].
 *
 * The age specification requires a scrypt recipient to be the only recipient.
 *
 * @param message detail about the error
 * @param cause underlying error
 */
public class InvalidScryptRecipientException
@JvmOverloads
constructor(message: String? = null, cause: Throwable? = null) : CryptoException(message, cause)

/**
 * Signals an incompatible stanza passed to [kage.Identity.unwrap].
 *
 * @param message detail about the error
 * @param cause underlying error
 */
public sealed class InvalidIdentityException
@JvmOverloads
constructor(message: String? = null, cause: Throwable? = null) : CryptoException(message, cause)

/**
 * Signals a failure while unwrapping an scrypt stanza with an [kage.Identity].
 *
 * @param message detail about the error
 * @param cause underlying error
 */
public class ScryptIdentityException
@JvmOverloads
constructor(message: String? = null, cause: Throwable? = null) :
  InvalidIdentityException(message, cause)

/**
 * Signals a failure while unwrapping an X25519 stanza with an [kage.Identity].
 *
 * @param message detail about the error
 * @param cause underlying error
 */
public class X25519IdentityException
@JvmOverloads
constructor(message: String? = null, cause: Throwable? = null) :
  InvalidIdentityException(message, cause)

/**
 * Signals a failure while unwrapping an ML-KEM-768-X25519 stanza with an [kage.Identity].
 *
 * @param message detail about the error
 * @param cause underlying error
 */
public class MlKem768X25519IdentityException
@JvmOverloads
constructor(message: String? = null, cause: Throwable? = null) :
  InvalidIdentityException(message, cause)

/**
 * Signals a failure while unwrapping an SSH stanza with an [kage.Identity].
 *
 * @param message detail about the error
 * @param cause underlying error
 */
public class SshIdentityException
@JvmOverloads
constructor(message: String? = null, cause: Throwable? = null) :
  InvalidIdentityException(message, cause)

/**
 * Signals an SSH key that cannot be parsed as a [kage.Recipient] or [kage.Identity].
 *
 * @param message detail about the error
 * @param cause underlying error
 */
public open class InvalidSshKeyException
@JvmOverloads
constructor(message: String? = null, cause: Throwable? = null) : CryptoException(message, cause)

/**
 * Signals an SSH key format or type that the implementation does not support.
 *
 * This includes passphrase-encrypted private keys and unsupported key types.
 *
 * @param message detail about the error
 * @param cause underlying error
 */
public class UnsupportedSshKeyException
@JvmOverloads
constructor(message: String? = null, cause: Throwable? = null) : CryptoException(message, cause)

/**
 * Signals a failed integrity check after decrypting a passphrase-encrypted OpenSSH private key.
 *
 * @param message detail about the error
 * @param cause underlying error
 */
public class IncorrectPassphraseException
@JvmOverloads
constructor(message: String? = null, cause: Throwable? = null) :
  InvalidSshKeyException(message, cause)

/**
 * Signals a disallowed all-zero shared secret from an X25519 low-order point.
 *
 * @param message detail about the error
 * @param cause underlying error
 */
public class X25519LowOrderPointException
@JvmOverloads
constructor(message: String? = null, cause: Throwable? = null) :
  InvalidIdentityException(message, cause)

/**
 * Signals decryption without any [kage.Identity]s.
 *
 * @param message detail about the error
 * @param cause underlying error
 */
public class NoIdentitiesException
@JvmOverloads
constructor(message: String? = null, cause: Throwable? = null) :
  InvalidIdentityException(message, cause)

/**
 * Signals ciphertext whose size does not meet the cryptographic operation's requirements.
 *
 * @param cause underlying error
 */
public class IncorrectCipherTextSizeException(cause: Throwable? = null) :
  CryptoException("Incorrect cipher text size", cause)

/**
 * Signals an identity that cannot decrypt a recipient block.
 *
 * The decryption code should try another identity or fail if none remain.
 *
 * @param cause underlying error
 */
public class IncorrectIdentityException(cause: Throwable? = null) :
  CryptoException("incorrect identity for recipient block", cause)

/**
 * Signals an error while streaming encrypted or decrypted data.
 *
 * @param message detail about the error
 * @param cause underlying error
 */
public class StreamException
@JvmOverloads
constructor(message: String? = null, cause: Throwable? = null) : CryptoException(message, cause)

/**
 * Signals a Base64 string that is not canonical under RFC 4648 section 3.5.
 *
 * @param message detail about the error
 * @param cause underlying error
 */
public class InvalidBase64StringException
@JvmOverloads
constructor(message: String? = null, cause: Throwable? = null) : CryptoException(message, cause)

/**
 * Signals an incorrect message authentication code (MAC).
 *
 * @param message detail about the error
 * @param cause underlying error
 */
public class IncorrectHMACException
@JvmOverloads
constructor(message: String? = null, cause: Throwable? = null) : CryptoException(message, cause)

/**
 * Signals a truncated MAC or one with an invalid size.
 *
 * @param message detail about the error
 * @param cause underlying error
 */
public class InvalidHMACHeaderException
@JvmOverloads
constructor(message: String? = null, cause: Throwable? = null) : CryptoException(message, cause)

/**
 * Signals an error while encoding or decoding armor data.
 *
 * @param message detail about the error
 * @param cause underlying error
 */
public class ArmorCodingException
@JvmOverloads
constructor(message: String? = null, cause: Throwable? = null) : CryptoException(message, cause)
