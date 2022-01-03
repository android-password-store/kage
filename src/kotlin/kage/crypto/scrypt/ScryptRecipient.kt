/**
 * Copyright 2021 The kage Authors. All rights reserved. Use of this source code is governed by
 * either an Apache 2.0 or MIT license at your discretion, that can be found in the LICENSE-APACHE
 * or LICENSE-MIT files respectively.
 */
package kage.crypto.scrypt

import kage.Recipient
import kage.format.AgeStanza

public class ScryptRecipient : Recipient {
  override fun wrap(fileKey: ByteArray): List<AgeStanza> {
    TODO("Not yet implemented")
  }
}
