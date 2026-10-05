/**
 * Copyright 2026 The kage Authors. All rights reserved. Use of this source code is governed by
 * either an Apache 2.0 or MIT license at your discretion, that can be found in the LICENSE-APACHE
 * or LICENSE-MIT files respectively.
 */
package kage.cli

import com.github.ajalt.clikt.core.CliktError
import com.github.ajalt.clikt.core.NoSuchOption
import com.github.ajalt.clikt.core.parse
import kotlin.system.exitProcess

fun main(args: Array<String>) {
  val command = AgeCommand()
  try {
    command.parse(args)
  } catch (failure: NoSuchOption) {
    command.echoFormattedHelp(failure)
    exitProcess(2)
  } catch (failure: CliktError) {
    command.echoFormattedHelp(failure)
    exitProcess(failure.statusCode)
  }
}
