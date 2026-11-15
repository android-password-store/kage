/**
 * Copyright 2025 The kage Authors. All rights reserved. Use of this source code is governed by
 * either an Apache 2.0 or MIT license at your discretion, that can be found in the LICENSE-APACHE
 * or LICENSE-MIT files respectively.
 */
package kage

import kage.format.AgeStanza

/**
 * Wraps file keys with labels that restrict recipient compatibility.
 *
 * A [Recipient] can implement this interface to use [wrapWithLabels] instead of [Recipient.wrap].
 * Encryption succeeds only when every recipient returns the same labels, regardless of order.
 * Recipients without this interface use an empty list of labels.
 *
 * This can be used to ensure a recipient is only used with other recipients with equivalent
 * properties (for example by setting a "postquantum" label) or to ensure a recipient is always used
 * alone (by returning a random label, for example to preserve its authentication properties).
 */
public interface RecipientWithLabels {
  /**
   * Wraps [fileKey] and returns its stanzas with labels describing recipient compatibility.
   *
   * The first element contains the recipient stanzas; the second contains labels that must match
   * those returned by every other recipient in an encryption operation.
   */
  public fun wrapWithLabels(fileKey: ByteArray): Pair<List<AgeStanza>, List<String>>
}
