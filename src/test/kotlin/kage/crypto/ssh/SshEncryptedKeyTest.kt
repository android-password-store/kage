/**
 * Copyright 2022 The kage Authors. All rights reserved. Use of this source code is governed by
 * either an Apache 2.0 or MIT license at your discretion, that can be found in the LICENSE-APACHE
 * or LICENSE-MIT files respectively.
 */
package kage.kage.crypto.ssh

import com.google.common.truth.Truth.assertThat
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import kage.Age
import kage.crypto.ssh.SshKey
import kage.errors.IncorrectPassphraseException
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows

/**
 * Real `ssh-keygen`-generated passphrase-encrypted private keys (ed25519 and RSA-2048, default
 * cipher/kdf: aes256-ctr + bcrypt) decrypting real `age`-CLI-produced ciphertext.
 *
 * Fixtures were generated with:
 * ```
 * ssh-keygen -t ed25519 -N 'correct horse battery staple' -f ed25519_key
 * ssh-keygen -t ed25519 -a 32 -N 'rounds32' -f ed25519_key_r32
 * ssh-keygen -t rsa -b 2048 -N 'another test passphrase!' -f rsa_key
 * age -R <pubkey> -a -o msg.age plaintext.txt   # plaintext: "the quick brown fox jumps over the lazy dog"
 * ```
 */
class SshEncryptedKeyTest {
  private val plaintext = "the quick brown fox jumps over the lazy dog".toByteArray()

  private val ed25519Key =
    """
    -----BEGIN OPENSSH PRIVATE KEY-----
    b3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jdHIAAAAGYmNyeXB0AAAAGAAAABCEadrXTx
    aOhmUjs6hZpl6LAAAAGAAAAAEAAAAzAAAAC3NzaC1lZDI1NTE5AAAAIAKu+ef59EStjgLM
    nERUf/w+dj+qTPBn2KAbrojH0p1pAAAAkJhBHRAgbon+CYRNpc0U1SLuHYafsmcpBn/NHO
    QoM51FpPdtz6uZ8vcEfXKFL0ccLAbseAaBMxiJUDKZJqZ6QcZtBQHkTIXtp5S5bXa757Pl
    1H1louqRWWOM64fJV7n73Q9Xl1eAjZq6EqsAXBSCI2RWFPPLw+fxLmEf1unuGsrpYdeWKJ
    W2QNmhUEUsp1x0ZA==
    -----END OPENSSH PRIVATE KEY-----
    """
      .trimIndent()

  private val ed25519MessageArmored =
    """
    -----BEGIN AGE ENCRYPTED FILE-----
    YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IHNzaC1lZDI1NTE5IGZlRjBvUSBZcjVN
    V1NJNmpnaWVBOXRpdlBTQW1vWm9BKzkrNDlsdDlKdWhmVDdqWlZjCjFpTWVjTWtn
    dlNmVjJsdE1qam9jQ1VnOG41dkJnMzBSVEZCTVhkY3ZzUFkKLS0tIDJWVDd1OFJi
    bDZnWnVEQ2Ntbko1S2xCdkwrNzNTUGVMNHY2RUpCb205T2sKhRUfWEPG+pE2Bcbo
    UdIEZaE0fOfTT7d020CP9lhDvkIjnXbKIK9gOeIxOEsbclyBZbRITKk/FjpRJqC7
    uZ1gpziEhqJAO7+gfEhr
    -----END AGE ENCRYPTED FILE-----
    """
      .trimIndent()

  // Same passphrase-encrypted key, but with `ssh-keygen -a 32` (bcrypt rounds=32 instead of the
  // default 16), to exercise the kdfoptions rounds field, not just its salt.
  private val ed25519KeyCustomRounds =
    """
    -----BEGIN OPENSSH PRIVATE KEY-----
    b3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jdHIAAAAGYmNyeXB0AAAAGAAAABBu+vrIiX
    OOXCL8uxsUSX7wAAAAIAAAAAEAAAAzAAAAC3NzaC1lZDI1NTE5AAAAIBLH8YY5VeLO3lD5
    jdVdbonnNqajJO0DJ7QNMUoMAkyJAAAAkPlVQQHDnibJfOpmfwXgEEEhUW8ddpB1wAkMlg
    N8ezRnFrvJEjjCFO+ZWnFdtDKSZCk19D30d0CRGeOt25PAw0tfR3eZxYO++rBdocaAftkK
    mngmsRx5bUG0OB55QbujxfDEp263OoTlplqn5fXMGnrOkRaYCjjjDQ5DfIF+7u95VnQKYB
    sPeUy7lS+bVMARcQ==
    -----END OPENSSH PRIVATE KEY-----
    """
      .trimIndent()

  private val ed25519CustomRoundsMessageArmored =
    """
    -----BEGIN AGE ENCRYPTED FILE-----
    YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IHNzaC1lZDI1NTE5IFR0VGhXQSBiY0ZI
    TDZzT2hEV3Q5YUE5OWVwNTl0RmtqbGRHM01NNEFCZDNuN0VaMEh3CmRXcjh1dkRp
    QVJaSzFzdHlnVDZtU0dTR2VvR0hOc3AyL1l1Mm5KeG5uQVEKLS0tIFA1WXMwOTVT
    YkNoV3h5WWkzQ242RlpuVFhmWEE5amU1b2N4d0JqVnhUSGcKqvgNjwIbuze8bZ9b
    /y7iIKyaIy0n2/0P3ogrXbfZH8Th3sacoidDNPhHbHGkozgcTkSbJXte82mC+wwz
    zTyN2ozF0clllRMB4Jq0
    -----END AGE ENCRYPTED FILE-----
    """
      .trimIndent()

  private val rsaKey =
    """
    -----BEGIN OPENSSH PRIVATE KEY-----
    b3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jdHIAAAAGYmNyeXB0AAAAGAAAABCXDlDN94
    Ly8lu3aQwEiwyNAAAAGAAAAAEAAAEXAAAAB3NzaC1yc2EAAAADAQABAAABAQCkzPGf41nF
    om3yubawTjcci+8FkvmGZRwbokc/eYVLV68tLKS9pdiYoF4DYL8YQTKORPa9UwMFvpnfWc
    sT9hiWtWSy6qfWMmyjYulGtHzY2+ZmFTf5IDVvpZEQhZp083X9FlsPMlzglNe/0ro6t7Mn
    K9J1vNXFKyuZjrRE4+zG8ACHNFoe5k7Bi0zusPKAI6KqRB14wBX1IEl+PNRzUReSDpjPUo
    ujZ7lvU74A7tuV0f9ghajNHuSZPap/PDjPUGY7lkyLqnYG32JmcWhV4d8LLlOeF/3Rx139
    hqHsC/w/DdgzAg9RGJEOzzv7sTmRKy4tC8y+IcadmzFLSmBBxjmrAAADwHDymjEECYPE2K
    BnDK1ykuLn24vbjTCoKDxsYljVxixxoiEPp4RAuXiRHGkBj7t9gvbd3kWjgWwnYD7U57Xo
    QadMMMqvRSopcO3DHQAwSdBQ0IJ/rzqFoWcpZsx8oPcm7HTXI3h+L0c9Uyyf3bZvGJQtgF
    7e0/OdWlFXEpatCEEPE0BwPdkgpCmfGjQZMbnKZJe+0YVu+1lHxEdsi56jc6Ou6EeerXON
    riIiUQZ1U4GoyMXoO4E6j+f2HS/VwEKuYqmKe3/1aDrk7Qw+AT1ZUAs0s34UHO5MOEJ1A8
    fbWI8clud1yBniT2/5lvf4x78XvixT8JEEbHje4gB60HHhQuD3S8npGbzhjLDzCmW9Ua6w
    m3qUcbf8VSPl0c2ffZPkMbhvd/ekVfvbkxYVZeBap01YVl/ljD2FDWa/U4jE63WVUV7D4x
    di5VvYWWnTXYnnBtQXH86EEXJg3sueAExyJLh0Ln5OOpqWlbZkpYMunRTjU1kBXEd/bTpL
    9+zMPUt1nrzR56yAWuTfCKHPtdEr+2mNte4nXZ3EHvQs5yV852Ur2pyW3e8ga09AYYc4Ca
    jvBP9fbD1u/r8bIIXtBdp04X6iQ7vswF0+8art5jQ1cmLk9qvm13QsFM4xelhPHj2+SnQJ
    3ya4/rHaFa0GGxFs1/JAvmnAnoebtKmPWcroqIgLH2QvpTvkqg+IxxA6wMaH713WD+eeFA
    ExJlPYRCRDBt3aO3guqGpWzmZixiVUAeehh+6xHjNGom3nbWQ+z+l1tuMIfpexzyFxLxDd
    AI/DtpWmB/lGEzJOgKHCeubYn70Bdr1K/tp8xrAXFW21BONqXB/T7Nmy6geOiy5U8I679C
    w32WXv+IchBvsHCNibAbYDVqISimAxBsF8yANHTSZc+2Zbw54tqV6tASETdEcfzBb2LaR2
    2DuJu0J667B9ZGASKbHKYXgCfowFwJCK4XV5LaOVFdtU5ZO8whn90Ie84yvRFPshKFBx2W
    Q0n+u4psmpth96sdTjtn9UQEimZh/E3nBeBZDkdmwCIoCcCxinMO9b42L78WRU3kxgdprC
    c++yZTPRep8Fu9kuClz6bm/4wXyRKSQxgppcYMSSwu7K33/kRyX+JkVuQ5GDjWZuejyaEg
    ZTjH0cm0QX1GXz0HJer2Vrp25Nxj7BpcniJQI00w/5D+TT5h2bpCYwcGfn4qHoXNoJxMFR
    aCjXk1zLu3YjtEu8ScMWlc8fKGzNYcQw5UtoPVnsD8liFog5QZxtbzIMiMnmJvllHlGPfD
    fhHy5G0g==
    -----END OPENSSH PRIVATE KEY-----
    """
      .trimIndent()

  private val rsaMessageArmored =
    """
    -----BEGIN AGE ENCRYPTED FILE-----
    YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IHNzaC1yc2EgVDBuaGNRCkFKT0dzeFJ1
    UDY0bFhaUC9uWlRIV3cvR2d0a0lSTlFnai9YUU8yU3NGTkpkQy9XM09KTEt6eGFz
    RGVyeG40KzMKN01rb0tUVS9IM1RrWjJXV2d3eFFMMFM0bktYVTZHSE42TGRvZlph
    OXI1VUJaRHd3ODl4dU9GM1Z0M21GOFdvRgpDS25pT3crWmNzSk5iRGJNeFlUVkpn
    YkhvWEtnb2lPeTdieGNxMHptQ1lndStoOExJREdxOFBvVkV5MFRXeWFECndYK1RV
    UkJFRWdrZGp2cTdaUVNaMkZpb3JhV3BJR2kzeW1GL1VXa0pvS2Nod2o2VmtPbUx2
    bkIwcmY2Q0JyRVYKUVFGMFlTeVN2K2pwK1NCNjVlZUJiNE9sRVFRSjF3VXA2TTRB
    UEg0R2dVS3FReHBwdmdEQ3IvYTVUaUpBR09MNwprY2FXKzg4WmNhSUtTWDdhNDNX
    RVl3Ci0tLSBCbGtPK1h1eUJJTWd2NG4vYlNDRXNRbzltTWZzVkVQcndMcTV5T1du
    dU9RChf4UCtpgkkZlyRnDo+UP1r6kMDi1+7FFaRtYz8z//vqLLiTdtTGvcm5Ktzy
    9cIoDw0JePxJ0Zt5H3wfaFIA/kTjvDvK/KjINqivVA==
    -----END AGE ENCRYPTED FILE-----
    """
      .trimIndent()

  private fun decrypt(identity: kage.Identity, armored: String): ByteArray {
    val out = ByteArrayOutputStream()
    Age.decryptStream(listOf(identity), armored.byteInputStream(), out)
    return out.toByteArray()
  }

  @Test
  fun ed25519_decryptsRealAgeCiphertextWithRealSshKeygenEncryptedKey() {
    val identity = SshKey.parseIdentity(ed25519Key, "correct horse battery staple".toByteArray())
    assertThat(decrypt(identity, ed25519MessageArmored)).isEqualTo(plaintext)
  }

  @Test
  fun ed25519_customBcryptRounds_decryptsRealAgeCiphertext() {
    val identity = SshKey.parseIdentity(ed25519KeyCustomRounds, "rounds32".toByteArray())
    assertThat(decrypt(identity, ed25519CustomRoundsMessageArmored)).isEqualTo(plaintext)
  }

  @Test
  fun rsa_decryptsRealAgeCiphertextWithRealSshKeygenEncryptedKey() {
    val identity = SshKey.parseIdentity(rsaKey, "another test passphrase!".toByteArray())
    assertThat(decrypt(identity, rsaMessageArmored)).isEqualTo(plaintext)
  }

  // golang.org/x/crypto/ssh/testdata/keys.go's own encrypted-key fixtures (passphrase "password"),
  // the test corpus behind age's own SSH support (age's agessh package delegates encrypted-key
  // parsing to x/crypto/ssh rather than implementing it). Cross-checked locally against
  // `ssh-keygen -y`. The CBC one exercises a cipher none of the fixtures above do.
  private val xCryptoSshAes256CtrKey =
    """
    -----BEGIN OPENSSH PRIVATE KEY-----
    b3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jdHIAAAAGYmNyeXB0AAAAGAAAABDKj29BlC
    ocEWuVhQ94/RjoAAAAEAAAAAEAAAAzAAAAC3NzaC1lZDI1NTE5AAAAIIw1gSurPTDwZidA
    2AIjQZgoQi3IFn9jBtFdP10/Jj7DAAAAoFGkQbB2teSU7ikUsnc7ct2aH3pitM359lNVUh
    7DQbJWMjbQFbrBYyDJP+ALj1/RZmP2yoIf7/wr99q53/pm28Xp1gGP5V2RGRJYCA6kgFIH
    xdB6KEw1Ce7Bz8JaDIeagAGd3xtQTH3cuuleVxCZZnk9NspsPxigADKCls/RUiK7F+z3Qf
    Lvs9+PH8nIuhFMYZgo3liqZbVS5z4Fqhyzyq4=
    -----END OPENSSH PRIVATE KEY-----
    """
      .trimIndent()
  private val xCryptoSshAes256CtrPublicKey =
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIIw1gSurPTDwZidA2AIjQZgoQi3IFn9jBtFdP10/Jj7D"

  private val xCryptoSshAes256CbcKey =
    """
    -----BEGIN OPENSSH PRIVATE KEY-----
    b3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jYmMAAAAGYmNyeXB0AAAAGAAAABDzGKF3uX
    G1gXALZKFd6Ir4AAAAEAAAAAEAAAAzAAAAC3NzaC1lZDI1NTE5AAAAIDne4/teO42zTDdj
    NwxUMNpbfmp/dxgU4ZNkC3ydgcugAAAAoJ3J/oA7+iqVOz0CIUUk9ufdP1VP4jDf2um+0s
    Sgs7x6Gpyjq67Ps7wLRdSmxr/G5b+Z8dRGFYS/wUCQEe3whwuImvLyPwWjXLzkAyMzc01f
    ywBGSrHnvP82ppenc2HuTI+E05Xc02i6JVyI1ShiekQL5twoqtR6pEBZnD17UonIx7cRzZ
    gbDGyT3bXMQtagvCwoW+/oMTKXiZP5jCJpEO8=
    -----END OPENSSH PRIVATE KEY-----
    """
      .trimIndent()
  private val xCryptoSshAes256CbcPublicKey =
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDne4/teO42zTDdjNwxUMNpbfmp/dxgU4ZNkC3ydgcug"

  @Test
  fun xCryptoSshFixture_aes256Ctr_roundTripsAgainstItsOwnPublicKey() {
    val recipient = SshKey.parseRecipient(xCryptoSshAes256CtrPublicKey)
    val identity = SshKey.parseIdentity(xCryptoSshAes256CtrKey, "password".toByteArray())
    val ciphertext = Age.encrypt(listOf(recipient), ByteArrayInputStream(plaintext))
    assertThat(Age.decrypt(identity, ciphertext).readBytes()).isEqualTo(plaintext)
  }

  @Test
  fun xCryptoSshFixture_aes256Cbc_roundTripsAgainstItsOwnPublicKey() {
    val recipient = SshKey.parseRecipient(xCryptoSshAes256CbcPublicKey)
    val identity = SshKey.parseIdentity(xCryptoSshAes256CbcKey, "password".toByteArray())
    val ciphertext = Age.encrypt(listOf(recipient), ByteArrayInputStream(plaintext))
    assertThat(Age.decrypt(identity, ciphertext).readBytes()).isEqualTo(plaintext)
  }

  @Test
  fun wrongPassphrase_throwsIncorrectPassphraseException() {
    assertThrows<IncorrectPassphraseException> {
      SshKey.parseIdentity(ed25519Key, "definitely the wrong passphrase".toByteArray())
    }
  }

  @Test
  fun noPassphraseGiven_throwsUnsupportedSshKeyException() {
    assertThrows<kage.errors.UnsupportedSshKeyException> { SshKey.parseIdentity(ed25519Key) }
  }

  @Test
  fun emptyPassphrase_throwsIncorrectPassphraseException() {
    assertThrows<IncorrectPassphraseException> { SshKey.parseIdentity(ed25519Key, ByteArray(0)) }
  }

  @Test
  fun roundsAboveCeiling_rejectedImmediately() {
    val tampered = tamperEncryptedKeyRounds(ed25519Key, rounds = 2_000_000_000L)
    assertThrows<kage.errors.UnsupportedSshKeyException> {
      SshKey.parseIdentity(tampered, "correct horse battery staple".toByteArray())
    }
  }
}
