/**
 * Copyright 2022 The kage Authors. All rights reserved. Use of this source code is governed by
 * either an Apache 2.0 or MIT license at your discretion, that can be found in the LICENSE-APACHE
 * or LICENSE-MIT files respectively.
 */
package kage

import kage.errors.IncorrectIdentityException
import kage.format.AgeStanza

/**
 * Unwraps an opaque file key from recipient stanzas during decryption.
 *
 * An identity can be a secret key, such as [kage.crypto.x25519.X25519Identity], a plugin, or a
 * custom implementation. [unwrap] must throw [IncorrectIdentityException] when no stanza matches;
 * other errors are fatal.
 *
 * [Age docs](https://github.com/FiloSottile/age/blob/ab3707c085f2c1/age.go#L59-L72)
 */
public interface Identity {
  /**
   * Unwraps the file key from a stanza in [stanzas].
   *
   * @throws IncorrectIdentityException if none of the stanzas match this identity
   */
  public fun unwrap(stanzas: List<AgeStanza>): ByteArray
}

internal fun multiUnwrap(unwrapFn: (AgeStanza) -> ByteArray, stanzas: List<AgeStanza>): ByteArray {
  val exceptions = mutableListOf<Exception>()

  stanzas.forEach { stanza ->
    try {
      return unwrapFn(stanza)
    } catch (err: IncorrectIdentityException) {
      // will try next stanza
      exceptions.add(err)
    }
  }

  throw exceptions.reduce { acc, exception -> acc.apply { addSuppressed(exception) } }
}
