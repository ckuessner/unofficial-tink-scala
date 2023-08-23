/*
Copyright (c) 2000-2023 The Legion of the Bouncy Castle Inc. (https://www.bouncycastle.org)

Permission is hereby granted, free of charge, to any person obtaining a copy of this software
and associated documentation files (the "Software"), to deal in the Software without restriction,
including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense,
and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so,
subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial
portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,
INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR
PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
DEALINGS IN THE SOFTWARE.
 */
package org.bouncycastle.crypto.digests

import org.bouncycastle.crypto.ExtendedDigest
import org.bouncycastle.util.Pack

/**
 * Base class for SHA-384 and SHA-512.
 */
abstract class LongDigest protected ()
  extends ExtendedDigest {

  private val xBuf = new Array[Byte](8)
  private var xBufOff = 0

  private var byteCount1 = 0L
  private var byteCount2 = 0L

  protected var H1: Long = 0L
  protected var H2: Long = 0L
  protected var H3: Long = 0L
  protected var H4: Long = 0L
  protected var H5: Long = 0L
  protected var H6: Long = 0L
  protected var H7: Long = 0L
  protected var H8: Long = 0L

  private val W = new Array[Long](80)
  private var wOff: Int = 0

  reset()

  /**
   * Copy constructor.  We are using copy constructors in place
   * of the Object.clone() interface as this interface is not
   * supported by J2ME.
   */
  protected def this(t: LongDigest) = {
    this()
    copyIn(t)
  }

  protected def copyIn(t: LongDigest): Unit = {
    System.arraycopy(t.xBuf, 0, xBuf, 0, t.xBuf.length)

    xBufOff = t.xBufOff
    byteCount1 = t.byteCount1
    byteCount2 = t.byteCount2

    H1 = t.H1
    H2 = t.H2
    H3 = t.H3
    H4 = t.H4
    H5 = t.H5
    H6 = t.H6
    H7 = t.H7
    H8 = t.H8

    System.arraycopy(t.W, 0, W, 0, t.W.length)
    wOff = t.wOff
  }

  override def update(in: Byte): Unit = {
    xBuf(xBufOff) = in
    xBufOff += 1

    if (xBufOff == xBuf.length) {
      processWord(xBuf, 0)
      xBufOff = 0
    }

    byteCount1 += 1
  }

  override def update(in: Array[Byte], _inOff: Int, _len: Int): Unit = {
    var inOff = _inOff
    var len = _len

    //
    // fill the current word
    //
    while ((xBufOff != 0) && (len > 0)) {
      update(in(inOff))

      inOff += 1
      len -= 1
    }

    //
    // process whole words.
    //
    while (len >= xBuf.length) {
      processWord(in, inOff)

      inOff += xBuf.length
      len -= xBuf.length
      byteCount1 += xBuf.length
    }

    //
    // load in the remainder.
    //
    while (len > 0) {
      update(in(inOff))
      inOff += 1
      len -= 1
    }
  }

  def finish(): Unit = {
    adjustByteCounts()

    val lowBitLength: Long = byteCount1 << 3
    val hiBitLength: Long = byteCount2

    //
    // add the pad bytes.
    //
    update(128.toByte)

    while (xBufOff != 0) {
      update(0.toByte)
    }

    processLength(lowBitLength, hiBitLength)

    processBlock()
  }

  override def reset(): Unit = {
    byteCount1 = 0
    byteCount2 = 0

    xBufOff = 0
    for (i <- 0 until xBuf.length) {
      xBuf(i) = 0
    }

    wOff = 0
    for (i <- 0 until W.length) {
      W(i) = 0
    }
  }

  override def getByteLength: Int = LongDigest.BYTE_LENGTH

  protected def processWord(in: Array[Byte], inOff: Int): Unit = {
    W(wOff) = Pack.bigEndianToLong(in, inOff)

    wOff += 1
    if (wOff == 16) processBlock()
  }

  /**
   * adjust the byte counts so that byteCount2 represents the
   * upper long (less 3 bits) word of the byte count.
   */
  private def adjustByteCounts(): Unit = {
    if (byteCount1 > 0x1fffffffffffffffL) {
      byteCount2 += (byteCount1 >>> 61)
      byteCount1 &= 0x1fffffffffffffffL
    }
  }

  protected def processLength(lowW: Long, hiW: Long): Unit = {
    if (wOff > 14) {
      processBlock()
    }

    W(14) = hiW
    W(15) = lowW
  }

  protected def processBlock(): Unit = {
    adjustByteCounts()

    //
    // expand 16 word block into 80 word blocks.
    //
    for (t <- 16 to 79) {
      W(t) = Sigma1(W(t - 2)) + W(t - 7) + Sigma0(W(t - 15)) + W(t - 16)
    }

    //
    // set up working variables.
    //
    var a: Long = H1
    var b: Long = H2
    var c: Long = H3
    var d: Long = H4
    var e: Long = H5
    var f: Long = H6
    var g: Long = H7
    var h: Long = H8

    var t: Int = 0

    for (i <- 0 until 10) {
      // t = 8 * i
      h += Sum1(e) + Ch(e, f, g) + LongDigest.K(t) + W({t += 1; t - 1})
      d += h
      h += Sum0(a) + Maj(a, b, c)

      // t = 8 * i + 1
      g += Sum1(d) + Ch(d, e, f) + LongDigest.K(t) + W({t += 1; t - 1})
      c += g
      g += Sum0(h) + Maj(h, a, b)

      // t = 8 * i + 2
      f += Sum1(c) + Ch(c, d, e) + LongDigest.K(t) + W({t += 1; t - 1})
      b += f
      f += Sum0(g) + Maj(g, h, a)

      // t = 8 * i + 3
      e += Sum1(b) + Ch(b, c, d) + LongDigest.K(t) + W({t += 1; t - 1})
      a += e
      e += Sum0(f) + Maj(f, g, h)

      // t = 8 * i + 4
      d += Sum1(a) + Ch(a, b, c) + LongDigest.K(t) + W({t += 1; t - 1})
      h += d
      d += Sum0(e) + Maj(e, f, g)

      // t = 8 * i + 5
      c += Sum1(h) + Ch(h, a, b) + LongDigest.K(t) + W({t += 1; t - 1})
      g += c
      c += Sum0(d) + Maj(d, e, f)

      // t = 8 * i + 6
      b += Sum1(g) + Ch(g, h, a) + LongDigest.K(t) + W({t += 1; t - 1})
      f += b
      b += Sum0(c) + Maj(c, d, e)

      // t = 8 * i + 7
      a += Sum1(f) + Ch(f, g, h) + LongDigest.K(t) + W({t += 1; t - 1})
      e += a
      a += Sum0(b) + Maj(b, c, d)
    }

    H1 += a
    H2 += b
    H3 += c
    H4 += d
    H5 += e
    H6 += f
    H7 += g
    H8 += h

    //
    // reset the offset and clean out the word buffer.
    //
    wOff = 0
    for (i <- 0 until 16) {
      W(i) = 0
    }
  }

  /* SHA-384 and SHA-512 functions (as for SHA-256 but for longs) */
  private def Ch(x: Long, y: Long, z: Long) = (x & y) ^ ((~(x)) & z)

  private def Maj(x: Long, y: Long, z: Long) = (x & y) ^ (x & z) ^ (y & z)

  private def Sum0(x: Long) = ((x << 36) | (x >>> 28)) ^ ((x << 30) | (x >>> 34)) ^ ((x << 25) | (x >>> 39))

  private def Sum1(x: Long) = ((x << 50) | (x >>> 14)) ^ ((x << 46) | (x >>> 18)) ^ ((x << 23) | (x >>> 41))

  private def Sigma0(x: Long) = ((x << 63) | (x >>> 1)) ^ ((x << 56) | (x >>> 8)) ^ (x >>> 7)

  private def Sigma1(x: Long) = ((x << 45) | (x >>> 19)) ^ ((x << 3) | (x >>> 61)) ^ (x >>> 6)
}

private[digests] object LongDigest {
  private val BYTE_LENGTH = 128

  /* SHA-384 and SHA-512 Constants
   * (represent the first 64 bits of the fractional parts of the
   * cube roots of the first sixty-four prime numbers)
   */
  private[digests] val K = Array(
    0x428a2f98d728ae22L, 0x7137449123ef65cdL, 0xb5c0fbcfec4d3b2fL, 0xe9b5dba58189dbbcL,
    0x3956c25bf348b538L, 0x59f111f1b605d019L, 0x923f82a4af194f9bL, 0xab1c5ed5da6d8118L,
    0xd807aa98a3030242L, 0x12835b0145706fbeL, 0x243185be4ee4b28cL, 0x550c7dc3d5ffb4e2L,
    0x72be5d74f27b896fL, 0x80deb1fe3b1696b1L, 0x9bdc06a725c71235L, 0xc19bf174cf692694L,
    0xe49b69c19ef14ad2L, 0xefbe4786384f25e3L, 0x0fc19dc68b8cd5b5L, 0x240ca1cc77ac9c65L,
    0x2de92c6f592b0275L, 0x4a7484aa6ea6e483L, 0x5cb0a9dcbd41fbd4L, 0x76f988da831153b5L,
    0x983e5152ee66dfabL, 0xa831c66d2db43210L, 0xb00327c898fb213fL, 0xbf597fc7beef0ee4L,
    0xc6e00bf33da88fc2L, 0xd5a79147930aa725L, 0x06ca6351e003826fL, 0x142929670a0e6e70L,
    0x27b70a8546d22ffcL, 0x2e1b21385c26c926L, 0x4d2c6dfc5ac42aedL, 0x53380d139d95b3dfL,
    0x650a73548baf63deL, 0x766a0abb3c77b2a8L, 0x81c2c92e47edaee6L, 0x92722c851482353bL,
    0xa2bfe8a14cf10364L, 0xa81a664bbc423001L, 0xc24b8b70d0f89791L, 0xc76c51a30654be30L,
    0xd192e819d6ef5218L, 0xd69906245565a910L, 0xf40e35855771202aL, 0x106aa07032bbd1b8L,
    0x19a4c116b8d2d0c8L, 0x1e376c085141ab53L, 0x2748774cdf8eeb99L, 0x34b0bcb5e19b48a8L,
    0x391c0cb3c5c95a63L, 0x4ed8aa4ae3418acbL, 0x5b9cca4f7763e373L, 0x682e6ff3d6b2b8a3L,
    0x748f82ee5defb2fcL, 0x78a5636f43172f60L, 0x84c87814a1f0ab72L, 0x8cc702081a6439ecL,
    0x90befffa23631e28L, 0xa4506cebde82bde9L, 0xbef9a3f7b2c67915L, 0xc67178f2e372532bL,
    0xca273eceea26619cL, 0xd186b8c721c0c207L, 0xeada7dd6cde0eb1eL, 0xf57d4f7fee6ed178L,
    0x06f067aa72176fbaL, 0x0a637dc5a2c898a6L, 0x113f9804bef90daeL, 0x1b710b35131c471bL,
    0x28db77f523047d84L, 0x32caab7b40c72493L, 0x3c9ebe0a15c9bebcL, 0x431d67c49c100d4cL,
    0x4cc5d4becb3e42b6L, 0x597f299cfc657e2aL, 0x5fcb6fab3ad6faecL, 0x6c44198c4a475817L
  )
}

