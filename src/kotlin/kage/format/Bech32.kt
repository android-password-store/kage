/**
 * Copyright 2022 The kage Authors. All rights reserved. Use of this source code is governed by
 * either an Apache 2.0 or MIT license at your discretion, that can be found in the LICENSE-APACHE
 * or LICENSE-MIT files respectively.
 */
package kage.format

import com.github.michaelbull.result.Err
import com.github.michaelbull.result.Ok
import com.github.michaelbull.result.Result
import com.github.michaelbull.result.map
import kage.errors.Bech32Exception

/**
 * age.go uses a modified implementation of bech32, so we translate the code from age.go into kotlin
 * here
 */
internal object Bech32 {
  private const val charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

  private val generator =
    intArrayOf(0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3).map { it.toUInt() }

  private fun polymod(values: ByteArray): UInt {
    var chk = 1u
    for (v in values) {
      val top = chk shr 25
      chk = (chk and 33554431u) shl 5
      chk = chk xor v.toByteUInt()
      for (i in 0 until 5) {
        val bit = top shr i and 1u
        if (bit == 1u) {
          chk = chk xor generator[i]
        }
      }
    }
    return chk
  }

  private fun hrpExpand(hrp: String): ByteArray {
    val h = hrp.lowercase().toByteArray()
    val ret = mutableListOf<Byte>()

    for (c in h) {
      ret.add((c.toByteUInt() shr 5).toByte())
    }

    ret.add(0)

    for (c in h) {
      ret.add((c.toByteUInt() and 31u).toByte())
    }

    return ret.toByteArray()
  }

  private fun verifyChecksum(hrp: String, data: ByteArray): Boolean =
    polymod(hrpExpand(hrp).plus(data)) == 1u

  private fun createChecksum(hrp: String, data: ByteArray): ByteArray {
    val values = hrpExpand(hrp).plus(data).plus(byteArrayOf(0, 0, 0, 0, 0, 0))
    val mod = polymod(values) xor 1u
    val ret = ByteArray(6)
    for (p in ret.indices) {
      val shift = 5 * (5 - p)
      ret[p] = ((mod shr shift) and 31u).toByte()
    }
    return ret
  }

  private fun convertBits(
    data: ByteArray,
    frombits: Byte,
    tobits: Byte,
    pad: Boolean
  ): Bech32Result<ByteArray> {
    val ret = mutableListOf<Byte>()
    var acc = 0u
    var bits = 0u.toByte()
    val maxv = ((1 shl tobits.toByteInt()) - 1).toByte()
    for ((idx, value) in data.withIndex()) {
      if (value.toByteUInt() shr frombits.toByteInt() != 0u) {
        return Err(Bech32Exception("invalid data range data[$idx]=$value (frombits=$frombits)"))
      }
      acc = acc shl frombits.toByteInt() or value.toByteUInt()
      bits = bits.plus(frombits).toByte()
      while (bits >= tobits) {
        bits = bits.minus(tobits).toByte()
        ret.add((acc shr bits.toByteInt() and maxv.toByteUInt()).toByte())
      }
    }
    if (pad) {
      if (bits > 0) {
        ret.add((acc shl (tobits - bits) and maxv.toByteUInt()).toByte())
      }
    } else if (bits >= frombits) {
      return Err(Bech32Exception("illegal zero padding"))
    } else if (acc shl (tobits - bits) and maxv.toByteUInt() != 0u) {
      return Err(Bech32Exception("non-zero padding"))
    }

    return Ok(ret.toByteArray())
  }

  //
  // Encode encodes the HRP and a bytes slice to Bech32. If the HRP is uppercase,
  // the output will be uppercase.
  fun encode(hrp: String, data: ByteArray): Bech32Result<String> {
    val values =
      when (val maybeValues = convertBits(data, 8, 5, true)) {
        is Err -> return maybeValues
        is Ok -> maybeValues.value
      }

    if (hrp.length + values.size + 7 > 90) {
      return Err(Bech32Exception("too long: hrp length=${hrp.length}, data length=${values.size}"))
    }
    if (hrp.isEmpty()) {
      return Err(Bech32Exception("invalid HRP: $hrp"))
    }
    for ((p, c) in hrp.withIndex()) {
      if ((c.code < 33) || (c.code > 126)) {
        return Err(Bech32Exception("invalid HRP character: hrp[$p]=$c"))
      }
    }
    if (hrp.uppercase() != hrp && hrp.lowercase() != hrp) {
      return Err(Bech32Exception("mixed case HRP: $hrp"))
    }
    val lower = hrp.lowercase() == hrp
    val lHrp = hrp.lowercase()
    val ret = StringBuilder()
    ret.append(lHrp)
    ret.append("1")
    for (p in values) {
      ret.append(charset[p.toByteInt()])
    }
    for (p in createChecksum(lHrp, values)) {
      ret.append(charset[p.toByteInt()])
    }
    if (lower) {
      return Ok(ret.toString())
    }
    return Ok(ret.toString().uppercase())
  }

  // Decode decodes a Bech32 string. If the string is uppercase, the HRP will be uppercase.
  fun decode(s: String): Bech32Result<Pair<String, ByteArray>> {
    if (s.length > 90) {
      return Err(Bech32Exception("too long: len=${s.length}"))
    }
    if (s.lowercase() != s && s.uppercase() != s) {
      return Err(Bech32Exception("mixed case"))
    }
    val pos = s.lastIndexOf("1")
    if (pos < 1 || pos + 7 > s.length) {
      return Err(Bech32Exception("separator '1' invalid at position pos=$pos, len=${s.length}"))
    }
    val hrp = s.slice(0 until pos)
    for ((p, c) in hrp.withIndex()) {
      if (c.code < 33 || c.code > 126) {
        return Err(Bech32Exception("Invalid character human-readable part: s[$p]=$c"))
      }
    }
    val sl = s.lowercase()
    val data = mutableListOf<Byte>()
    for ((p, c) in sl.slice(pos + 1 until sl.length).withIndex()) {
      val d = charset.indexOf(c)
      if (d == -1) {
        return Err(Bech32Exception("invalid character data part: s[$p]=$c"))
      }
      data.add(d.toByte())
    }
    val dataArray = data.toByteArray()
    if (!verifyChecksum(hrp, dataArray)) {
      return Err(Bech32Exception("invalid checksum"))
    }

    val convertedBits = convertBits(dataArray.sliceArray(0 until data.size - 6), 5, 8, false)

    return convertedBits.map { Pair(hrp, it) }
  }
}

public typealias Bech32Result<T> = Result<T, Bech32Exception>

internal fun Byte.toByteUInt(): UInt = this.toUInt() and 255u

internal fun Byte.toByteInt(): Int = this.toInt() and 0xff
