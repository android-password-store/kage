package kage

import kage.format.AgeStanza

/**
 * [RecipientWithLabels] can be optionally implemented by a [Recipient], in which
 * case Encrypt will use WrapWithLabels instead of Wrap.
 *
 * [Age.encrypt] will succeed only if the labels returned by all the recipients
 * (assuming the empty set for those that don't implement [RecipientWithLabels])
 * are the same.
 *
 * This can be used to ensure a recipient is only used with other recipients
 * with equivalent properties (for example by setting a "postquantum" label) or
 * to ensure a recipient is always used alone (by returning a random label, for
 * example to preserve its authentication properties).
 */
public interface RecipientWithLabels {
  public fun wrapWithLabels(fileKey: ByteArray): Pair<List<AgeStanza>, List<String>>
}
