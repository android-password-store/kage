/**
 * Copyright 2022 The kage Authors. All rights reserved. Use of this source code is governed by
 * either an Apache 2.0 or MIT license at your discretion, that can be found in the LICENSE-APACHE
 * or LICENSE-MIT files respectively.
 */
package kage

import kage.format.AgeStanza

/**
 * Wraps an opaque file key into recipient stanzas during encryption.
 *
 * Implementations can represent public keys, plugins, or custom recipients. They must return no
 * more than one stanza per actual recipient.
 *
 * [Age docs](https://github.com/FiloSottile/age/blob/ab3707c085f2c1/age.go#L76-L85)
 */
public interface Recipient {
  /** Wraps [fileKey] for this recipient. */
  public fun wrap(fileKey: ByteArray): List<AgeStanza>
}
