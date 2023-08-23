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

import org.bouncycastle.util.Pack

/**
 * FIPS 180-2 implementation of SHA-512.
 *
 * <pre>
 * block  word  digest
 * SHA-1   512    32    160
 * SHA-256 512    32    256
 * SHA-384 1024   64    384
 * SHA-512 1024   64    512
 * </pre>
 */

class SHA512Digest extends LongDigest {
  reset()

  /**
   * Copy constructor.  This will copy the state of the provided
   * message digest.
   */
  def this(t: SHA512Digest) = {
    this()
    super.copyIn(t)
  }

  override def getAlgorithmName = "SHA-512"

  override def getDigestSize: Int = SHA512Digest.DIGEST_LENGTH

  override def doFinal(out: Array[Byte], outOff: Int): Int = {
    finish()

    Pack.longToBigEndian(H1, out, outOff)
    Pack.longToBigEndian(H2, out, outOff + 8)
    Pack.longToBigEndian(H3, out, outOff + 16)
    Pack.longToBigEndian(H4, out, outOff + 24)
    Pack.longToBigEndian(H5, out, outOff + 32)
    Pack.longToBigEndian(H6, out, outOff + 40)
    Pack.longToBigEndian(H7, out, outOff + 48)
    Pack.longToBigEndian(H8, out, outOff + 56)

    reset()

    SHA512Digest.DIGEST_LENGTH
  }

  /**
   * reset the chaining variables
   */
  override def reset(): Unit = {
    super.reset()

    /* SHA-512 initial hash value
     * The first 64 bits of the fractional parts of the square roots
     * of the first eight prime numbers
     */
    H1 = 0x6a09e667f3bcc908L
    H2 = 0xbb67ae8584caa73bL
    H3 = 0x3c6ef372fe94f82bL
    H4 = 0xa54ff53a5f1d36f1L
    H5 = 0x510e527fade682d1L
    H6 = 0x9b05688c2b3e6c1fL
    H7 = 0x1f83d9abfb41bd6bL
    H8 = 0x5be0cd19137e2179L
  }
}

private[digests] object SHA512Digest {
  private[digests] val DIGEST_LENGTH = 64
}
