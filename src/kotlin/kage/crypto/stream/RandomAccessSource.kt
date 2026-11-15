/**
 * Copyright 2022 The kage Authors. All rights reserved. Use of this source code is governed by
 * either an Apache 2.0 or MIT license at your discretion, that can be found in the LICENSE-APACHE
 * or LICENSE-MIT files respectively.
 */
package kage.crypto.stream

import java.nio.ByteBuffer
import java.nio.channels.FileChannel

/**
 * Reads bytes at arbitrary offsets without changing position state.
 *
 * Implementations must be thread safe. Like [FileChannel.read], [readAt] may return fewer bytes
 * than requested, so callers needing an exact count must loop.
 */
public fun interface RandomAccessSource {
  /**
   * Reads up to [length] bytes at [sourceOffset] into [dst] starting at [destOffset].
   *
   * A read may return fewer than [length] bytes, even before reaching the end; loop when an exact
   * count is required. Returns `-1` when [sourceOffset] is at or past the end.
   *
   * @param dst destination byte array
   * @param destOffset start index in [dst]
   * @param length maximum number of bytes to read
   * @param sourceOffset byte offset in the source
   * @return bytes read, or `-1` at or beyond end of source
   */
  public fun readAt(dst: ByteArray, destOffset: Int, length: Int, sourceOffset: Long): Int

  public companion object {
    /** Wraps a [FileChannel]; its positional [FileChannel.read] is already thread safe. */
    @JvmStatic
    public fun of(channel: FileChannel): RandomAccessSource =
      RandomAccessSource { dst, destOffset, length, sourceOffset ->
        channel.read(ByteBuffer.wrap(dst, destOffset, length), sourceOffset)
      }
  }
}
