/**
 * Copyright 2026 The kage Authors. All rights reserved. Use of this source code is governed by
 * either an Apache 2.0 or MIT license at your discretion, that can be found in the LICENSE-APACHE
 * or LICENSE-MIT files respectively.
 */
package kage

import kage.format.AgeStanza

/**
 * Returns a file key obtained out of band, for example through [Age.decryptHeader].
 *
 * [unwrap] ignores the stanzas. Use the key only with its corresponding file; a different file's
 * header MAC will not match.
 *
 * @param fileKey raw file key to return
 */
public class InjectedFileKeyIdentity(private val fileKey: ByteArray) : Identity {
  /** Returns the supplied file key without inspecting [stanzas]. */
  override fun unwrap(stanzas: List<AgeStanza>): ByteArray = fileKey
}
