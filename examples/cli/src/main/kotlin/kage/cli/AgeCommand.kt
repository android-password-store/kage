/**
 * Copyright 2026 The kage Authors. All rights reserved. Use of this source code is governed by
 * either an Apache 2.0 or MIT license at your discretion, that can be found in the LICENSE-APACHE
 * or LICENSE-MIT files respectively.
 */
package kage.cli

import com.github.ajalt.clikt.core.CliktCommand
import com.github.ajalt.clikt.core.Context
import com.github.ajalt.clikt.core.ProgramResult
import com.github.ajalt.clikt.parameters.arguments.argument
import com.github.ajalt.clikt.parameters.arguments.default
import com.github.ajalt.clikt.parameters.groups.mutuallyExclusiveOptions
import com.github.ajalt.clikt.parameters.groups.single
import com.github.ajalt.clikt.parameters.options.flag
import com.github.ajalt.clikt.parameters.options.multiple
import com.github.ajalt.clikt.parameters.options.option
import com.github.ajalt.clikt.parameters.options.switch
import kage.Age
import kage.Recipient
import kage.crypto.scrypt.ScryptIdentity
import kage.crypto.scrypt.ScryptRecipient

private const val VERSION = "kage 0.1.0"

private enum class Mode {
  ENCRYPT,
  DECRYPT,
}

internal class AgeCommand : CliktCommand(name = "age") {
  override val printHelpOnEmptyArgs: Boolean = true
  private val mode by
    mutuallyExclusiveOptions<Mode>(
        option(help = "Encrypt the input to the output.")
          .switch("-e" to Mode.ENCRYPT, "--encrypt" to Mode.ENCRYPT),
        option(help = "Decrypt the input to the output.")
          .switch("-d" to Mode.DECRYPT, "--decrypt" to Mode.DECRYPT),
      )
      .single()
  private val armor by option("-a", "--armor", help = "Encrypt to a PEM encoded format.").flag()
  private val passphrase by option("-p", "--passphrase", help = "Encrypt with a passphrase.").flag()
  private val output by
    option("-o", "--output", help = "Write the result to the file at path OUTPUT.")
  private val recipientArgs by
    option("-r", "--recipient", help = "Encrypt to the specified RECIPIENT.").multiple()
  private val recipientFiles by
    option("-R", "--recipients-file", help = "Encrypt to recipients listed at PATH.").multiple()
  private val identityFiles by
    option("-i", "--identity", help = "Use the identity file at PATH.").multiple()
  private val version by option("--version", help = "Print the version.").flag()
  private val input by argument("INPUT").default("-")

  override fun help(context: Context): String = "Encrypt or decrypt files using age."

  override fun run() {
    if (version) {
      echo(VERSION)
      return
    }

    try {
      when (mode ?: Mode.ENCRYPT) {
        Mode.ENCRYPT -> encrypt()
        Mode.DECRYPT -> decrypt()
      }
    } catch (failure: Exception) {
      reportFailure(failure.message ?: "operation failed")
    }
  }

  private fun encrypt() {
    if (identityFiles.isNotEmpty() && mode != Mode.ENCRYPT) {
      throw CliFailure("-i can only be used when encrypting with --encrypt")
    }

    val recipients = selectedRecipients()
    val encryptionRecipients =
      if (passphrase) {
        if (recipients.isNotEmpty()) throw CliFailure("--passphrase cannot be used with recipients")
        listOf(
          ScryptRecipient(
            PasswordPrompt.read("Enter passphrase (leave empty to autogenerate a secure one): ")
              .toByteArray()
          )
        )
      } else {
        if (recipients.isEmpty()) throw CliFailure("no recipients specified")
        recipients
      }

    CliStreams.process(input, output) { source, destination ->
      Age.encryptStream(encryptionRecipients, source, destination, armor)
    }
  }

  private fun decrypt() {
    if (recipientArgs.isNotEmpty() || recipientFiles.isNotEmpty() || passphrase || armor) {
      throw CliFailure("recipient options cannot be used when decrypting")
    }

    val identities =
      identityFiles.flatMap(KeyMaterial::readIdentities).ifEmpty {
        listOf(ScryptIdentity(PasswordPrompt.read("Enter passphrase: ").toByteArray()))
      }
    CliStreams.process(input, output) { source, destination ->
      Age.decryptStream(identities, source, destination)
    }
  }

  private fun selectedRecipients(): List<Recipient> =
    recipientArgs.map(KeyMaterial::decodeRecipient) +
      recipientFiles.flatMap(KeyMaterial::readRecipients) +
      if (mode == Mode.ENCRYPT) {
        identityFiles.flatMap(KeyMaterial::readIdentities).map(KeyMaterial::recipientFromIdentity)
      } else {
        emptyList()
      }

  private fun reportFailure(message: String): Nothing {
    System.err.println("age: $message")
    throw ProgramResult(1)
  }
}
