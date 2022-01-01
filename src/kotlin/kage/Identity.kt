package kage

import kage.format.AgeStanza

/*
 * Age docs:
 * An Identity is passed to Decrypt to unwrap an opaque file key from a
 * recipient stanza. It can be for example a secret key like X25519Identity, a
 * plugin, or a custom implementation.
 *
 * Unwrap must return an error wrapping IncorrectIdentityError if none of the
 * recipient stanzas match the identity, any other error will be considered
 * fatal.
 *
 */
public interface Identity {
  public fun unwrap(stanzas: List<AgeStanza>): ByteArray
}