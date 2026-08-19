/**
 * Copyright 2022 The kage Authors. All rights reserved. Use of this source code is governed by
 * either an Apache 2.0 or MIT license at your discretion, that can be found in the LICENSE-APACHE
 * or LICENSE-MIT files respectively.
 */
package kage.crypto.stream

import java.nio.ByteBuffer
import java.nio.channels.FileChannel

/**
 * A byte source readable at an arbitrary offset without disturbing any position state, kage's
 * equivalent of Go's `io.ReaderAt`. Implementations must be thread safe. Mirrors
 * [FileChannel.read]'s contract: a call may return fewer than [length] bytes even mid-source, so
 * callers needing an exact count must loop.
 */
public fun interface RandomAccessSource {
  /**
   * Reads up to [length] bytes starting at [sourceOffset] into [dst] starting at [destOffset].
   * Returns the number of bytes actually read, or -1 if [sourceOffset] is at or past the end.
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
