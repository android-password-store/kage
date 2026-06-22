/**
 * Copyright 2026 The kage Authors. All rights reserved. Use of this source code is governed by
 * either an Apache 2.0 or MIT license at your discretion, that can be found in the LICENSE-APACHE
 * or LICENSE-MIT files respectively.
 */
package kage.kage.crypto.ssh

import java.io.ByteArrayOutputStream
import java.util.Base64
import kage.crypto.ssh.SshWireReader

internal fun buildEd25519AuthorizedKey(publicKey: ByteArray, comment: String = "test"): String {
  val blob =
    ByteArrayOutputStream().apply {
      writeSshString("ssh-ed25519".toByteArray(Charsets.US_ASCII))
      writeSshString(publicKey)
    }

  return "ssh-ed25519 ${Base64.getEncoder().encodeToString(blob.toByteArray())} $comment"
}

/**
 * Rewrites an Ed25519 OpenSSH private key so every serialized public-key field points at
 * [replacementAuthorizedKey], while the 32-byte private seed remains unchanged.
 *
 * OpenSSH stores the public key twice in this format: once as the top-level public key blob and
 * once again inside the private-key section next to the seed. This helper rewrites both copies to
 * the replacement key but preserves the original private seed bytes.
 *
 * The result is a deliberately inconsistent key file: the metadata says "this is key B" while the
 * secret material still belongs to key A. `SshKey.parseIdentity()` should reject that mismatch.
 */
internal fun tamperEd25519PrivateKeyPublicParts(
  privateKeyPem: String,
  replacementAuthorizedKey: String,
): String {
  val replacementBlob = decodeAuthorizedKeyBlob(replacementAuthorizedKey)
  val replacementPublicKey =
    SshWireReader(replacementBlob).run {
      readString() // type
      readString()
    }

  val blob = decodeOpenSshPem(privateKeyPem)
  val reader = SshWireReader(blob)
  val magic = reader.readRaw(AUTH_MAGIC.size)
  val cipherName = reader.readString()
  val kdfName = reader.readString()
  val kdfOptions = reader.readString()
  val numKeys = reader.readUInt32()
  reader.readString() // original public key blob
  val privateSection = reader.readString()

  val privateReader = SshWireReader(privateSection)
  val check1 = privateReader.readUInt32()
  val check2 = privateReader.readUInt32()
  val keyType = privateReader.readString()
  privateReader.readString() // original public key
  val privateKeyBytes = privateReader.readString()
  val comment = privateReader.readString()
  val padding = privateReader.readRaw(privateReader.remaining())

  val rewrittenPrivateSection =
    ByteArrayOutputStream().apply {
      writeUInt32(check1)
      writeUInt32(check2)
      writeSshString(keyType)
      writeSshString(replacementPublicKey)
      writeSshString(privateKeyBytes)
      writeSshString(comment)
      write(padding)
    }

  val rewrittenBlob =
    ByteArrayOutputStream().apply {
      write(magic)
      writeSshString(cipherName)
      writeSshString(kdfName)
      writeSshString(kdfOptions)
      writeUInt32(numKeys)
      writeSshString(replacementBlob)
      writeSshString(rewrittenPrivateSection.toByteArray())
    }

  return encodeOpenSshPem(rewrittenBlob.toByteArray())
}

/**
 * Rewrites only the top-level public-key blob of an RSA OpenSSH private key to use
 * [replacementAuthorizedKey], leaving the serialized RSA private key parameters untouched.
 *
 * That creates a private key file whose fingerprinting/toplevel public metadata refers to one RSA
 * key while the CRT parameters still describe another. `SshKey.parseIdentity()` should detect and
 * reject this inconsistency instead of accepting the tampered file.
 */
internal fun tamperRsaPrivateKeyOuterPublicKey(
  privateKeyPem: String,
  replacementAuthorizedKey: String,
): String {
  val replacementBlob = decodeAuthorizedKeyBlob(replacementAuthorizedKey)

  val blob = decodeOpenSshPem(privateKeyPem)
  val reader = SshWireReader(blob)
  val magic = reader.readRaw(AUTH_MAGIC.size)
  val cipherName = reader.readString()
  val kdfName = reader.readString()
  val kdfOptions = reader.readString()
  val numKeys = reader.readUInt32()
  reader.readString() // original public key blob
  val privateSection = reader.readString()

  val rewrittenBlob =
    ByteArrayOutputStream().apply {
      write(magic)
      writeSshString(cipherName)
      writeSshString(kdfName)
      writeSshString(kdfOptions)
      writeUInt32(numKeys)
      writeSshString(replacementBlob)
      writeSshString(privateSection)
    }

  return encodeOpenSshPem(rewrittenBlob.toByteArray())
}

internal fun encodeOpenSshPem(blob: ByteArray): String {
  val body = Base64.getMimeEncoder(64, "\n".toByteArray()).encodeToString(blob)
  return "-----BEGIN OPENSSH PRIVATE KEY-----\n$body\n-----END OPENSSH PRIVATE KEY-----"
}

private fun decodeOpenSshPem(pem: String): ByteArray {
  val begin = "-----BEGIN OPENSSH PRIVATE KEY-----"
  val end = "-----END OPENSSH PRIVATE KEY-----"
  val body = pem.substringAfter(begin).substringBefore(end).replace(Regex("\\s"), "")
  return Base64.getDecoder().decode(body)
}

private fun decodeAuthorizedKeyBlob(authorizedKey: String): ByteArray {
  val fields = authorizedKey.trim().split(Regex("\\s+"))
  return Base64.getDecoder().decode(fields[1])
}

private fun ByteArrayOutputStream.writeUInt32(value: Long) {
  write(
    byteArrayOf(
      ((value ushr 24) and 0xff).toByte(),
      ((value ushr 16) and 0xff).toByte(),
      ((value ushr 8) and 0xff).toByte(),
      (value and 0xff).toByte(),
    )
  )
}

private fun ByteArrayOutputStream.writeSshString(value: ByteArray) {
  writeUInt32(value.size.toLong())
  write(value)
}

private val AUTH_MAGIC = "openssh-key-v1".toByteArray(Charsets.US_ASCII).plus(0x00.toByte())
