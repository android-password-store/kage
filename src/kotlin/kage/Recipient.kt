/**
 * Copyright 2022 The kage Authors. All rights reserved. Use of this source code is governed by
 * either an Apache 2.0 or MIT license at your discretion, that can be found in the LICENSE-APACHE
 * or LICENSE-MIT files respectively.
 */
package kage

import kage.format.AgeStanza

/*
 * From the age docs:
 * A Recipient is passed to Encrypt to wrap an opaque file key to one or more
 * recipient stanza(s). It can be for example a public key like X25519Recipient,
 * a plugin, or a custom implementation.
 * https://github.com/FiloSottile/age/blob/ab3707c085f2c1fdfd767a2ed718423e3925f4c4/age.go#L76-L85
 *
 * From the rage docs:
 * Implementations MUST NOT return more than one stanza per "actual recipient".
 * https://github.com/str4d/rage/blob/main/age/src/lib.rs#L225-L239
 */
public interface Recipient {
  public fun wrap(fileKey: ByteArray): List<AgeStanza>
}
