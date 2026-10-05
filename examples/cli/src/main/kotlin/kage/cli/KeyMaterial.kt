/**
 * Copyright 2026 The kage Authors. All rights reserved. Use of this source code is governed by
 * either an Apache 2.0 or MIT license at your discretion, that can be found in the LICENSE-APACHE
 * or LICENSE-MIT files respectively.
 */
package kage.cli

import java.io.BufferedReader
import java.io.File
import java.io.InputStreamReader
import java.io.StringReader
import kage.Age
import kage.Identity
import kage.Recipient
import kage.crypto.mlkem.MlKem768X25519Identity
import kage.crypto.mlkem.MlKem768X25519Recipient
import kage.crypto.ssh.SshEd25519Identity
import kage.crypto.ssh.SshKey
import kage.crypto.ssh.SshRsaIdentity
import kage.crypto.x25519.X25519Identity
import kage.crypto.x25519.X25519Recipient

internal class CliFailure(message: String) : RuntimeException(message)

internal object KeyMaterial {
  fun decodeRecipient(encoded: String): Recipient =
    try {
      when {
        encoded.startsWith("ssh-rsa ") || encoded.startsWith("ssh-ed25519 ") ->
          SshKey.parseRecipient(encoded)
        encoded.startsWith("age1pq") -> MlKem768X25519Recipient.decode(encoded)
        encoded.startsWith("age1") -> X25519Recipient.decode(encoded)
        else -> throw IllegalArgumentException("unknown recipient type")
      }
    } catch (_: Exception) {
      throw CliFailure("invalid recipient: $encoded")
    }

  fun readRecipients(path: String): List<Recipient> =
    try {
      val recipients = mutableListOf<Recipient>()
      openReader(path).useLines { lines ->
        lines
          .map(String::trim)
          .filter { it.isNotEmpty() && !it.startsWith("#") }
          .forEach { line ->
            if (line.startsWith("ssh-rsa ") || line.startsWith("ssh-ed25519 ")) {
              recipients += SshKey.parseRecipient(line)
            } else {
              recipients += Age.parseRecipients(BufferedReader(StringReader(line)))
            }
          }
      }
      if (recipients.isEmpty()) throw CliFailure("no recipients found")
      recipients
    } catch (failure: Exception) {
      if (failure is CliFailure) throw failure
      throw CliFailure("failed to parse recipients file $path: ${failure.message}")
    }

  fun readIdentities(path: String): List<Identity> =
    try {
      val contents = openReader(path).use { it.readText() }.trim()
      if (contents.startsWith("-----BEGIN OPENSSH PRIVATE KEY-----")) {
        listOf(SshKey.parseIdentity(contents))
      } else {
        Age.parseIdentities(BufferedReader(StringReader(contents)))
      }
    } catch (failure: Exception) {
      if (failure is CliFailure) throw failure
      throw CliFailure("failed to parse identities file $path: ${failure.message}")
    }

  fun recipientFromIdentity(identity: Identity): Recipient =
    when (identity) {
      is X25519Identity -> identity.recipient()
      is MlKem768X25519Identity -> identity.recipient()
      is SshRsaIdentity -> identity.recipient()
      is SshEd25519Identity -> identity.recipient()
      else -> throw CliFailure("identity type cannot be used as an encryption recipient")
    }

  private fun openReader(path: String): BufferedReader =
    if (path == "-") BufferedReader(InputStreamReader(System.`in`)) else File(path).bufferedReader()
}
