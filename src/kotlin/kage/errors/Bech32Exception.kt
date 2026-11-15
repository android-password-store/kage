/**
 * Copyright 2022 The kage Authors. All rights reserved. Use of this source code is governed by
 * either an Apache 2.0 or MIT license at your discretion, that can be found in the LICENSE-APACHE
 * or LICENSE-MIT files respectively.
 */
package kage.errors

/**
 * Signals an error while encoding or decoding Bech32 data.
 *
 * @param message detail about the encoding or decoding error
 * @param cause underlying error
 */
public class Bech32Exception
@JvmOverloads
constructor(message: String? = null, cause: Throwable? = null) : Exception(message, cause)
