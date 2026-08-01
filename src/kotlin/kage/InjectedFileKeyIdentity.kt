/**
 * Copyright 2026 The kage Authors. All rights reserved. Use of this source code is governed by
 * either an Apache 2.0 or MIT license at your discretion, that can be found in the LICENSE-APACHE
 * or LICENSE-MIT files respectively.
 */
package kage

import kage.format.AgeStanza

/**
 * An [Identity] that unconditionally returns [fileKey], allowing the use of a file key obtained
 * out-of-band, for example via [Age.decryptHeader].
 *
 * The stanzas it is handed are ignored, so the file key is only correct for the file it was
 * obtained from. Decryption still fails on any other file because the header MAC will not match.
 *
 * @param fileKey Raw file key to unwrap to.
 */
public class InjectedFileKeyIdentity(private val fileKey: ByteArray) : Identity {
  override fun unwrap(stanzas: List<AgeStanza>): ByteArray = fileKey
}
