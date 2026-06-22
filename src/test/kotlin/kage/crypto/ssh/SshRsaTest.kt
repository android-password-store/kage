/**
 * Copyright 2022 The kage Authors. All rights reserved. Use of this source code is governed by
 * either an Apache 2.0 or MIT license at your discretion, that can be found in the LICENSE-APACHE
 * or LICENSE-MIT files respectively.
 */
package kage.kage.crypto.ssh

import com.google.common.truth.Truth.assertThat
import java.io.ByteArrayInputStream
import java.util.Random
import kage.Age
import kage.crypto.ssh.SshKey
import kage.crypto.ssh.SshRsaIdentity
import kage.crypto.ssh.SshRsaRecipient
import kage.errors.InvalidSshKeyException
import kage.format.AgeFile
import org.bouncycastle.util.encoders.Base64
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows

class SshRsaTest {
  // A fixed 2048-bit RSA keypair generated with `ssh-keygen -t rsa -b 2048`, used so the tests
  // exercise real OpenSSH encodings rather than synthetic ones.
  private val publicKey =
    "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDWnremrBKJ8WUcIQltVZ4MD65ck7HFKwjAWY6lRAKLOj1ffwX8" +
      "lY0pIDe2Gry381CsuYIDfS21Iulfn0ZbYnb1qKxDGtwvasCplNv5Ag9JhznbO0aGNOfjXuuJI+ZM3AuZkYKQysEUFT2" +
      "47Oj9mvcU6qcTDF3E6kYDL2iFVqTUtQ4Vf/JMs4fdsUUqZeeXVl7mav+ctpmLU285qUQJxbHvoFUeUL9J9LnLQrYx4x" +
      "CdUibW0jvpKzRMcZ7wMz1954Jj2ThYJqBG228hUto9BS++epK40NIeQOvCYLwKM7ejVWI4xcHqNJ2+FZ95gXElkkcgn" +
      "V/mDNz1KE42kq4LhSeh kage-ssh-rsa-test"

  private val privateKey =
    """
    -----BEGIN OPENSSH PRIVATE KEY-----
    b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABFwAAAAdzc2gtcn
    NhAAAAAwEAAQAAAQEA1p63pqwSifFlHCEJbVWeDA+uXJOxxSsIwFmOpUQCizo9X38F/JWN
    KSA3thq8t/NQrLmCA30ttSLpX59GW2J29aisQxrcL2rAqZTb+QIPSYc52ztGhjTn417riS
    PmTNwLmZGCkMrBFBU9uOzo/Zr3FOqnEwxdxOpGAy9ohVak1LUOFX/yTLOH3bFFKmXnl1Ze
    5mr/nLaZi1NvOalECcWx76BVHlC/SfS5y0K2MeMQnVIm1tI76Ss0THGe8DM9feeCY9k4WC
    agRttvIVLaPQUvvnqSuNDSHkDrwmC8CjO3o1ViOMXB6jSdvhWfeYFxJZJHIJ1f5gzc9ShO
    NpKuC4UnoQAAA8gy8vyOMvL8jgAAAAdzc2gtcnNhAAABAQDWnremrBKJ8WUcIQltVZ4MD6
    5ck7HFKwjAWY6lRAKLOj1ffwX8lY0pIDe2Gry381CsuYIDfS21Iulfn0ZbYnb1qKxDGtwv
    asCplNv5Ag9JhznbO0aGNOfjXuuJI+ZM3AuZkYKQysEUFT247Oj9mvcU6qcTDF3E6kYDL2
    iFVqTUtQ4Vf/JMs4fdsUUqZeeXVl7mav+ctpmLU285qUQJxbHvoFUeUL9J9LnLQrYx4xCd
    UibW0jvpKzRMcZ7wMz1954Jj2ThYJqBG228hUto9BS++epK40NIeQOvCYLwKM7ejVWI4xc
    HqNJ2+FZ95gXElkkcgnV/mDNz1KE42kq4LhSehAAAAAwEAAQAAAQAKc8rmbWFuweimdM5w
    ene6xyW7AP9qppSjx4jMsDH+hVzZUoagXUk1bEoCTq2LuOggLV2xXU6VUIi0nT1wNGyuPK
    N9FikMjyKob6VB7JGBh3owHOQro5Z6ipQmhu7PpfTTqxREiHdcSseJgtI7DanEZUQzR4om
    jbFQtOWeftCCwmK9v2+y+HcNt7ill8XaogdJEoAMR4nJg3BJDq9tiVGab5MR0e/dogk4bD
    8AP5Op/rktAK1Wuqk3Vr7COGySzYhy0/plcAGgl912uCHrpyMfaY0N9k56Ro3ArxykZxmT
    foRBWqs3OvrnaLqeBW9JtRj5vJcb8Qm7w4twnuB9+z9RAAAAgGsUKAqbhXo+G5aYqa6Tb7
    DfiBVmmPYd0K9tAiAP4FXIURwU00+eySJMdqe1u7wFPHMWKs1M5rhC5Q3p0XpDlGVMo4Tm
    2tGI/CB34MASk/V6rCn+D1ShEuTPnh+on0+TSijW3WAvkmqGh4E5r/XkIxNlSgFHMsXmOh
    pzjAtLL6kyAAAAgQD0phov83echz4QARmnevZojTxb4o4UJNduEY1qHY5Nb3WREXycR5Nx
    3MGU0SUlq8+z7Mg4ThAGl8IGM+LELQ1DeEHZ/k9Gr1RSgabDpcYk+PybK6Il+beDJfpXQ6
    3YjevYIEn+SxI6QQrxdb6wggDXpg9dkWgrdh2d42QY/2RimQAAAIEA4JPv//Rw6frFjQCt
    93N4AsW4GrYpPNQ/01GeP6Wx4I9kX7hKSVewE2tou8vkUuK4bzTiQ6iUt1xXXIDJSCaimi
    qo5VNfULiX+ID8Q4YY8RnvlSL/6q1oOIcn8lG48d1R+o5QNM0taAJLbK+uCMsoyoG1OPgN
    h5WEd2erX/tdmkkAAAARa2FnZS1zc2gtcnNhLXRlc3QBAg==
    -----END OPENSSH PRIVATE KEY-----
    """
      .trimIndent()

  private val alternatePublicKey =
    "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCol7YjhrNPP1EFFeV7JfbjwIQBUM+Ky9L+N2qyZLWR1bj7RIk7T4VFnox7tPsKEFS3b3YhsbNWpeiesMczivgzxiYMIsbgYY3LR0Q8+QXvihKSLdnfPxx6EKcL2go5eGtHaJO0IjXILQIsP0ER1OeTIN6aOXvgnq2Pe96D8AGTJltuyvK4TD/CC1WE5F+88Gvy7gH/7vd6QGcQqevXy36dRkyNdHUgcnufOhwQmetDq4gsW4GxNPufzbm1PMVkmA7d87Zwig1JQAV/bcQnHIHNo7QgRds7tjOSIQ7vzl+pTbf677FWlQSR9QziKBuk1TQcTluwOXoYOnOZ9vmy2XTZ test2"

  @Test
  fun testWrapUnwrap() {
    val recipient = SshRsaRecipient.parse(publicKey)

    val fileKey = ByteArray(Age.FILE_KEY_SIZE)
    Random().nextBytes(fileKey)

    val stanza = recipient.wrap(fileKey).single()
    assertThat(stanza.type).isEqualTo("ssh-rsa")
    assertThat(stanza.args).hasSize(1)

    val identity = SshKey.parseIdentity(privateKey)
    val unwrapped = identity.unwrap(listOf(stanza))
    assertThat(unwrapped.asList()).containsExactlyElementsIn(fileKey.asList())
  }

  @Test
  fun testRecipientFromIdentityRoundTrips() {
    val identity = SshKey.parseIdentity(privateKey)
    val recipient = (identity as SshRsaIdentity).recipient()

    val fileKey = ByteArray(Age.FILE_KEY_SIZE)
    Random().nextBytes(fileKey)

    val stanzas = recipient.wrap(fileKey)
    assertThat(identity.unwrap(stanzas).asList()).containsExactlyElementsIn(fileKey.asList())
  }

  @Test
  fun testAgeRoundTrip() {
    val recipient = SshKey.parseRecipient(publicKey)
    val identity = SshKey.parseIdentity(privateKey)

    val plaintext = "the quick brown fox jumps over the lazy dog".toByteArray()
    val ageFile = Age.encrypt(listOf(recipient), ByteArrayInputStream(plaintext))
    val decrypted = Age.decrypt(identity, ageFile).readBytes()

    assertThat(decrypted).isEqualTo(plaintext)
  }

  @Test
  fun testDecryptsReferenceAgeCiphertext() {
    // A binary age file produced by the reference age implementation with `age -R <pubKey>` over
    // the plaintext below. Decrypting it proves byte-level interop of the ssh-rsa stanza
    // (fingerprint tag, RSA-OAEP with SHA-256/MGF1-SHA256 and the age label), which a kage-only
    // round-trip cannot, since a consistent deviation from age would still pass that.
    val ageEncrypted =
      Base64.decode(
        """
        YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IHNzaC1yc2EgZjVvdlJnCkhza044U2hw
        cDRmM2d0UnppYWRmSGt1NndYYy9lL05iN042L29ySnZVenFYOWRNaTVCejlKVTdI
        N2x6NWhHVW0KZjQvRWNoVE5uL2dlOGNqNTNTT3BCc2dBMHdGbVNLeFFxQ3Noa04x
        MlVUTHZiSE1wN0VRblpjTEtZRXBDVm5JVwpSZXBheStWd1JnVCtCQkNTN1Y2Y3R5
        MGxXT1FzaWNqVEFWRTZ0VThPTnAvMHFtQ2xIc1hqMGVIN3VDdDdSeHVuCmVHYStv
        QythTVVKbmxXYkNkKytpMHpJbldNd0xXNVpGT2NjK1RiVWFYRnJJMG8rdmxyZHlG
        Y3N1RHlqRklreXMKdjFaa3lDamtNai8rZEQ0ZkI5Y1dXNFVrc1JTUVpld21CM1V6
        UFlvWlU4Z1VwUCtmZkFDZGxlNkQ4UEo3MHpVQQpHQWJDZ2Q2Q2l1dHBlc3F4L2hI
        Qmx3Ci0tLSBkL29EWHFRbU9DR2Zmd1VHR21jNUVXbGRhU1dXRXhmelk3QXNkaUhZ
        Yzc0Ch/PtV3OSNsKmwZmfp6t9sOSYMui61EIsjPzzb8drkuf2OdIlXOmRMOacVV1
        W9oRogUbB1v0V0gbt4qt
        """
          .trimIndent()
      )

    val identity = SshKey.parseIdentity(privateKey)
    val ageFile = AgeFile.parse(ByteArrayInputStream(ageEncrypted))
    val decrypted = Age.decrypt(identity, ageFile).readBytes()

    assertThat(String(decrypted)).isEqualTo("kage ssh-rsa interop vector")
  }

  @Test
  fun testParseIdentityRejectsMismatchedRsaPublicKey() {
    val tamperedPrivateKey = tamperRsaPrivateKeyOuterPublicKey(privateKey, alternatePublicKey)

    assertThrows<InvalidSshKeyException> { SshKey.parseIdentity(tamperedPrivateKey) }
  }

  @Test
  fun testParseRejectsGarbage() {
    assertThrows<InvalidSshKeyException> { SshRsaRecipient.parse("not a key") }
  }
}
