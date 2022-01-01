package kage

import kage.format.AgeStanza

/*
 * Age docs:
 * A Recipient is passed to Encrypt to wrap an opaque file key to one or more
 * recipient stanza(s). It can be for example a public key like X25519Recipient,
 * a plugin, or a custom implementation.
 *
 * Rage docs:
 * Implementations MUST NOT return more than one stanza per "actual recipient".
 */
public interface Recipient {
  public fun wrap(fileKey: ByteArray): List<AgeStanza>
}
