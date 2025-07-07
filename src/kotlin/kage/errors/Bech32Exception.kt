/**
 * Copyright 2022 The kage Authors. All rights reserved. Use of this source code is governed by
 * either an Apache 2.0 or MIT license at your discretion, that can be found in the LICENSE-APACHE
 * or LICENSE-MIT files respectively.
 */
package kage.errors

/** Thrown when encoding or decoding Bech32 */
public class Bech32Exception
@JvmOverloads
constructor(message: String? = null, cause: Throwable? = null) : Exception(message, cause)
