/**
 * Copyright 2022 The kage Authors. All rights reserved. Use of this source code is governed by
 * either an Apache 2.0 or MIT license at your discretion, that can be found in the LICENSE-APACHE
 * or LICENSE-MIT files respectively.
 */
package kage.crypto.x25519

import at.favre.lib.crypto.HKDF
import com.github.michaelbull.result.getOrThrow
import com.github.michaelbull.result.mapError
import kage.Age
import kage.Identity
import kage.crypto.stream.ChaCha20Poly1305
import kage.crypto.x25519.X25519Recipient.Companion.MAC_KEY_LENGTH
import kage.crypto.x25519.X25519Recipient.Companion.X25519_INFO
import kage.errors.IncorrectCipherTextSizeException
import kage.errors.IncorrectIdentityException
import kage.errors.InvalidIdentityException
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

    if (stanza.args.size != 1) throw InvalidIdentityException("invalid x25519 recipient block")

    val stanzaPublicKey = stanza.args[0].decodeBase64()

    if (stanzaPublicKey.size != POINT_SIZE)
      throw InvalidIdentityException("invalid x25519 recipient block")

    val sharedSecret = X25519.scalarMult(secretKey, stanzaPublicKey)

    val salt = stanzaPublicKey.plus(this.publicKey)

    val hkdf = HKDF.fromHmacSha256()

    val wrappingKey =
      hkdf.extractAndExpand(salt, sharedSecret, X25519_INFO.toByteArray(), MAC_KEY_LENGTH)

    try {
      return ChaCha20Poly1305.aeadDecrypt(wrappingKey, stanza.body, Age.FILE_KEY_SIZE)
    } catch (err: IncorrectCipherTextSizeException) {
      throw err
    } catch (err: Exception) {
      throw IncorrectIdentityException(err)
    }
  }

  override fun unwrap(stanzas: List<AgeStanza>): ByteArray {
    return multiUnwrap(::unwrapSingle, stanzas)
  }

  public fun encodeToString(): String =
    Bech32.encode(AgeKeyFile.AGE_SECRET_KEY_PREFIX, secretKey).getOrThrow()

  public companion object {

    public fun decode(string: String): X25519Identity {
      val (hrp, key) =
        Bech32.decode(string)
          .mapError { InvalidIdentityException("Invalid public key", it) }
          .getOrThrow()

      if (key.size != POINT_SIZE)
        throw InvalidIdentityException("Invalid X25519 private key size: (${key.size})")

      if (hrp != AgeKeyFile.AGE_SECRET_KEY_PREFIX)
        throw InvalidIdentityException("Invalid human readable part for age secret key ($hrp)")

      val publicKey = X25519.scalarMultBase(key)

      return X25519Identity(key, publicKey)
    }
  }
}
