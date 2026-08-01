/**
 * Copyright 2026 The kage Authors. All rights reserved. Use of this source code is governed by
 * either an Apache 2.0 or MIT license at your discretion, that can be found in the LICENSE-APACHE
 * or LICENSE-MIT files respectively.
 */
package kage.kage.crypto.mlkem

import com.github.michaelbull.result.getOrThrow
import com.google.common.truth.Truth.assertThat
import java.io.ByteArrayOutputStream
import java.util.Random
import kage.Age
import kage.crypto.mlkem.MlKem768X25519Identity
import kage.crypto.mlkem.MlKem768X25519Recipient
import kage.crypto.x25519.X25519Identity
import kage.errors.IncorrectCipherTextSizeException
import kage.errors.IncorrectIdentityException
import kage.errors.InvalidRecipientException
import kage.errors.InvalidScryptRecipientException
import kage.errors.MlKem768X25519IdentityException
import kage.format.AgeFile
import kage.format.AgeHeader
import kage.format.AgeStanza
import kage.format.Bech32
import kage.utils.decodeBase64
import kage.utils.encodeBase64
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows

class MlKem768X25519RecipientTest {

  private val testIdentity =
    MlKem768X25519Identity.decode(
      "AGE-SECRET-KEY-PQ-1HZLGZUPT4ETPKDEV8HSGFDCYZ4E522W0A7PU2LHT8EH9W6YLNC3SW78XKG"
    )

  private fun wrapFileKey(): AgeStanza {
    val fileKey = ByteArray(Age.FILE_KEY_SIZE)
    Random().nextBytes(fileKey)
    return testIdentity.recipient().wrap(fileKey).first()
  }

  @Test
  fun testWrapUnwrap() {
    val identity = MlKem768X25519Identity.new()
    val recipient = identity.recipient()

    val fileKey = ByteArray(Age.FILE_KEY_SIZE)
    Random().nextBytes(fileKey)

    val (stanzas, labels) = recipient.wrapWithLabels(fileKey)
    val stanza = stanzas.first()

    assertThat(stanza.type).isEqualTo("mlkem768x25519")
    assertThat(stanza.args).hasSize(1)
    assertThat(stanza.args.first().decodeBase64()).hasLength(1120)
    assertThat(stanza.body).hasLength(Age.FILE_KEY_SIZE + 16)
    assertThat(labels).containsExactly("postquantum")

    val unwrapped = identity.unwrap(listOf(stanza))

    assertThat(fileKey).asList().containsExactlyElementsIn(unwrapped.asList())
  }

  @Test
  fun testEncryptDecrypt() {
    val identity = MlKem768X25519Identity.new()
    val plainText = "The quick brown fox jumps over the lazy dog"

    val ageFile = Age.encrypt(listOf(identity.recipient()), plainText.byteInputStream())

    val out = ByteArrayOutputStream()
    Age.decrypt(identity, ageFile).use { it.copyTo(out) }

    assertThat(out.toString()).isEqualTo(plainText)
  }

  @Test
  fun testRejectsMixingWithX25519() {
    val recipients =
      listOf(MlKem768X25519Identity.new().recipient(), X25519Identity.new().recipient())

    assertThrows<InvalidScryptRecipientException> {
      Age.encrypt(recipients, "".byteInputStream())
    }
  }

  @Test
  fun testEncodeDecodeIdentity() {
    val identity = MlKem768X25519Identity.new()
    val encoded = identity.encodeToString()

    assertThat(encoded).startsWith("AGE-SECRET-KEY-PQ-1")
    assertThat(MlKem768X25519Identity.decode(encoded).encodeToString()).isEqualTo(encoded)
  }

  @Test
  fun testRecipientDerivation() {
    // Recipient for [testIdentity] as derived by age.
    assertThat(testIdentity.recipient().encodeToString())
      .isEqualTo(
        "age1pq1z4f9zeapqujpskesfxhujkg525ymk8mep9up4wa7kxsycgvtc3ef0fqrrs79pszxh3gu7zyl2k5r4drv44smvshlqfwwl7ycrg2vd24k8ut9fdwevmrx44jzrqgzq473xwp8xefy5zt48f4f4ggkvduppkes9q7pjkdmjugrvkvq3vnhyuk20skhkscaypuq3zeu20dcgxwcnzsg2gmv8uyurlvhpx9s4xe8qxeq709c5s2a63nxekcjy7aav5a8je8csgyc4m4uvz9tz6s9tpuu0yqns7raa0gx5t6x4qv3j2phzyje60q4tlmm60vhz85pvmhcs88fs44rp6vcqapjszdv5yy0kc9s7sqggdwg5yx9q4llx76ts345njwrszv360dhwf3w3ffeu3qg9d4g6s2mwhgggzt68qk0y5hxlpa9e37fzn2k0z7tzwtwuf6cdkm0655c9r09x8w602vke986h6362cprm86uy67sqgzjc9tuuyck4egpz2l4rz69xlgg6wumzu4jynqtp8c6t4srycfkdjj0wzqrad9qpztxyf92eq3vl323j7mlra9p8vrtq648vkkqcjjczksm9z4epfwu4tn6xuu0sgyykyggqzxsf3zudjv33pww9gyxz9fm3caxf3mu8nsc3z68sgkhsej2ae6vmw8vvgjlp3c2cm9ac6a9q9ae08y5hs4hktu4rz7kkcujf4580l5qp7e0zpj454frja2aht9j6s9gkpwww73vr3wrdpa438c554l80j670fp4stx3n5zylq7qgzmm9gmzzzasfq2zjhz06494xqfsywwsqun866dz8kaw0758ejgn5d0axshwuxsjwxnpl99q5exr5ynrg9jkdgulrgzwynjnn9wpyxudr24dvejy8yraask8z3uksyvnndcjd9jcgcjhd2j2g8tv8lu08xzl4vmrquctdcputtdhw4tlqavt75dwtsdq3rgxhk75ftadquumkgl00kxxvuqfztmyqpugq5wq2jh9766lln55y26x3sd403sl6jk9agwxjsz9ggwxj54czrnwd2ruw73c2g35mfut9w548w9wwqtue76msnangew3t7qwd8lusy6evgnd4ryn6mn2ew605r6ztqnrcxvls2u4yr6mzy7ek6vazlyfj5jq0pqnsnwc8v4jt8we2qptcnrhajjzhggvwjke09sep3yzh3j2hhevh25pf98qshc63vkw6nzvcv39xlaqw4g0t8cg6fsk7fr967ezssuxj827gpt2p30vq2275e4z42rpvlyqv5vfkgzpqwjnqh9kax34pht69vcm8fpaupur6cdsqn7pqedrx76xmffvkzurxduxfm5md2h8zhmw8syq7wxtnfr8knpec8h88drcynzm7594njqy39nvk7py57zms4e64uapwwrphjmu4ktdx48hmjsv0cwtfmm2a04cfwahr385xwjszvymwvpxnr23x8kf4watqch9llz95gvnrzqezuvmfshattpthutm50je7kjgs4a4vx9hwyc6mly64ss3cn5j2ue2c00xy6tw5psjuafnyxnjvwcuff2ntx7vvwmt6knfg46t0tunsa35asg4vc5yxqyujfvtyhlx8yy24p29jxfkq45mm0tv5fjpvghyxsc0mpryklfqa0kpgx47hpk49zsjw3erxm62cpx9rxqpxaqagsr3u5c2aycgd43q98yy5z0zpyg28rya4upnre6ps2aq9f70wvljf2948c95w4ef2cvnqfvsw5t75ju2nf524lktxfgc3nnjy32dpap32pay27n9vvml5g8uvsu9hv67l0xn76vmjpa4glwu0q4pxnp4zq0xpqusdthwyj84sue9t0jv5rg6pvkedvxguq06ktvsyv397zmxwrqqnmc60gnhas8sccjjwu0rnsa3"
      )
  }

  @Test
  fun testEncodeDecodeRecipient() {
    val recipient = MlKem768X25519Identity.new().recipient()
    val encoded = recipient.encodeToString()

    assertThat(encoded).startsWith("age1pq1")
    assertThat(MlKem768X25519Recipient.decode(encoded).encodeToString()).isEqualTo(encoded)
  }

  @Test
  fun testIgnoresOtherStanzaTypes() {
    val stanza = wrapFileKey()

    assertThrows<IncorrectIdentityException> {
      testIdentity.unwrap(listOf(AgeStanza("MLKEM768X25519", stanza.args, stanza.body)))
    }
  }

  @Test
  fun testRejectsMalformedMatchingStanzaBeforeValidStanza() {
    val validStanza = wrapFileKey()
    val malformedStanza = AgeStanza(validStanza.type, emptyList(), validStanza.body)

    assertThrows<MlKem768X25519IdentityException> {
      testIdentity.unwrap(listOf(malformedStanza, validStanza))
    }
  }

  @Test
  fun testRejectsMalformedMatchingStanzaBeforeAnotherIdentityCanDecrypt() {
    val x25519Identity = X25519Identity.new()
    val ageFile = Age.encrypt(listOf(x25519Identity.recipient()), "plaintext".byteInputStream())
    val fileKey = x25519Identity.unwrap(ageFile.header.recipients)
    val malformedStanza = AgeStanza("mlkem768x25519", emptyList(), ByteArray(0))
    val header = AgeHeader.withMac(listOf(malformedStanza).plus(ageFile.header.recipients), fileKey)
    val malformedAgeFile = AgeFile(header, ageFile.body)

    assertThrows<MlKem768X25519IdentityException> {
      Age.decrypt(listOf(testIdentity, x25519Identity), malformedAgeFile)
    }
  }

  @Test
  fun testRejectsExtraArgument() {
    val stanza = wrapFileKey()

    assertThrows<MlKem768X25519IdentityException> {
      testIdentity.unwrap(listOf(AgeStanza(stanza.type, stanza.args.plus("extra"), stanza.body)))
    }
  }

  @Test
  fun testRejectsNonCanonicalEnc() {
    val stanza = wrapFileKey()
    val nonCanonical = stanza.args.first().dropLast(1).plus("/")

    assertThrows<MlKem768X25519IdentityException> {
      testIdentity.unwrap(listOf(AgeStanza(stanza.type, listOf(nonCanonical), stanza.body)))
    }
  }

  @Test
  fun testRejectsShortEnc() {
    val stanza = wrapFileKey()
    val short = stanza.args.first().decodeBase64().copyOfRange(0, 1119).encodeBase64()

    assertThrows<MlKem768X25519IdentityException> {
      testIdentity.unwrap(listOf(AgeStanza(stanza.type, listOf(short), stanza.body)))
    }
  }

  @Test
  fun testRejectsBodyOfWrongSize() {
    val stanza = wrapFileKey()

    assertThrows<IncorrectCipherTextSizeException> {
      testIdentity.unwrap(listOf(AgeStanza(stanza.type, stanza.args, stanza.body.plus(0))))
    }
  }

  @Test
  fun testIdentityCopiesSeedBeforeDerivingKeyPair() {
    val seed = ByteArray(32) { it.toByte() }
    val identity = MlKem768X25519Identity(seed)
    val expectedRecipient = identity.recipient().encodeToString()

    seed.fill(0)

    assertThat(
        MlKem768X25519Identity.decode(identity.encodeToString()).recipient().encodeToString()
      )
      .isEqualTo(expectedRecipient)
  }

  @Test
  fun testRecipientCopiesPublicKey() {
    val publicKey = Bech32.decode(testIdentity.recipient().encodeToString()).getOrThrow().second
    val recipient = MlKem768X25519Recipient(publicKey)
    val expectedEncoding = recipient.encodeToString()

    publicKey.fill(0)

    assertThat(recipient.encodeToString()).isEqualTo(expectedEncoding)
  }

  @Test
  fun testDecodeRejectsMalformedMlKemPublicKey() {
    val malformedKey = Bech32.encode("age1pq", ByteArray(1216) { 0xff.toByte() }).getOrThrow()

    assertThrows<InvalidRecipientException> { MlKem768X25519Recipient.decode(malformedKey) }
  }

  @Test
  fun testDecodeRejectsLowOrderX25519PublicKey() {
    val publicKey = Bech32.decode(testIdentity.recipient().encodeToString()).getOrThrow().second
    publicKey.fill(0, publicKey.size - 32, publicKey.size)
    val malformedKey = Bech32.encode("age1pq", publicKey).getOrThrow()

    assertThrows<InvalidRecipientException> { MlKem768X25519Recipient.decode(malformedKey) }
  }

  @Test
  fun testRejectsWrongSecretKeySize() {
    assertThrows<MlKem768X25519IdentityException> { MlKem768X25519Identity(ByteArray(31)) }
  }

  @Test
  fun testRejectsWrongPublicKeySize() {
    assertThrows<InvalidRecipientException> {
      MlKem768X25519Recipient(ByteArray(1217)).wrap(ByteArray(Age.FILE_KEY_SIZE))
    }
  }

  @Test
  fun testRejectsX25519Identity() {
    assertThrows<MlKem768X25519IdentityException> {
      MlKem768X25519Identity.decode(
        "AGE-SECRET-KEY-1EGTZVFFV20835NWYV6270LXYVK2VKNX2MMDKWYKLMGR48UAWX40Q2P2LM0"
      )
    }
  }
}
