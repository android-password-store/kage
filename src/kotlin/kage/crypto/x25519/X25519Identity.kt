/**
 * Copyright 2022 The kage Authors. All rights reserved. Use of this source code is governed by
 * either an Apache 2.0 or MIT license at your discretion, that can be found in the LICENSE-APACHE
 * or LICENSE-MIT files respectively.
 */
package kage.crypto.x25519

import at.favre.lib.hkdf.HKDF
import com.github.michaelbull.result.getOrThrow
import com.github.michaelbull.result.mapError
import java.security.SecureRandom
import kage.Age
import kage.Identity
import kage.crypto.stream.ChaCha20Poly1305
import kage.crypto.x25519.X25519Recipient.Companion.MAC_KEY_LENGTH
import kage.crypto.x25519.X25519Recipient.Companion.X25519_INFO
import kage.errors.IncorrectIdentityException
import kage.errors.X25519IdentityException
import kage.format.AgeKeyFile
import kage.format.AgeStanza
import kage.format.Bech32
import kage.multiUnwrap
import kage.utils.decodeBase64
import org.bouncycastle.math.ec.rfc7748.X25519.POINT_SIZE

public class X25519Identity(private val secretKey: ByteArray, private val publicKey: ByteArray) :
  Identity {

  private fun unwrapSingle(stanza: AgeStanza): ByteArray {
    if (stanza.type != X25519Recipient.X25519_STANZA_TYPE) throw IncorrectIdentityException()

    try {
      if (stanza.args.size != 1) throw X25519IdentityException("invalid x25519 recipient block")

      val stanzaPublicKey = stanza.args[0].decodeBase64()

      if (stanzaPublicKey.size != POINT_SIZE)
        throw X25519IdentityException("invalid x25519 recipient block")

      val sharedSecret = X25519.scalarMult(secretKey, stanzaPublicKey)

      val salt = stanzaPublicKey.plus(this.publicKey)

      val hkdf = HKDF.fromHmacSha256()

      val wrappingKey =
        hkdf.extractAndExpand(salt, sharedSecret, X25519_INFO.toByteArray(), MAC_KEY_LENGTH)

      return ChaCha20Poly1305.aeadDecrypt(wrappingKey, stanza.body, Age.FILE_KEY_SIZE)
    } catch (err: Exception) {
      if (err is X25519IdentityException) {
        throw err
      } else {
        throw X25519IdentityException("Error occurred while unwrapping stanza", err)
      }
    }
  }

  override fun unwrap(stanzas: List<AgeStanza>): ByteArray {
    return multiUnwrap(::unwrapSingle, stanzas)
  }

  public fun recipient(): X25519Recipient = X25519Recipient(publicKey)

  public fun encodeToString(): String =
    Bech32.encode(AgeKeyFile.AGE_SECRET_KEY_PREFIX, secretKey).getOrThrow()

  public companion object {

    public fun decode(string: String): X25519Identity {
      val (hrp, key) =
        Bech32.decode(string)
          .mapError { X25519IdentityException("Invalid public key", it) }
          .getOrThrow()

      if (key.size != POINT_SIZE)
        throw X25519IdentityException("Invalid X25519 private key size: (${key.size})")

      if (hrp != AgeKeyFile.AGE_SECRET_KEY_PREFIX)
        throw X25519IdentityException("Invalid human readable part for age secret key ($hrp)")

      val publicKey = X25519.scalarMultBase(key)

      return X25519Identity(key, publicKey)
    }

    /** Generates a new [kage.crypto.x25519.X25519Identity] with a random private key. */
    public fun new(): X25519Identity {
      val privateKey = ByteArray(POINT_SIZE)
      SecureRandom().nextBytes(privateKey)

      return X25519Identity(privateKey, X25519.scalarMultBase(privateKey))
    }
  }
}
