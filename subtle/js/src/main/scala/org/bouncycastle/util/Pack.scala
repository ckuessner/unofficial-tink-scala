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
package org.bouncycastle.util

/**
 * Utility methods for converting byte arrays into ints and longs, and back again.
 */
object Pack {
  def bigEndianToInt(bs: Array[Byte], _off: Int): Int = {
    var off = _off

    var n = bs(off) << 24
    n |= (bs({off += 1; off}) & 0xff) << 16
    n |= (bs({off += 1; off}) & 0xff) << 8
    n |= (bs({off += 1; off}) & 0xff)
    n
  }

  def intToBigEndian(n: Int, bs: Array[Byte], _off: Int): Unit = {
    var off = _off
    bs(off) = (n >>> 24).toByte
    bs({off += 1; off}) = (n >>> 16).toByte
    bs({off += 1; off}) = (n >>> 8).toByte
    bs({off += 1; off}) = n.toByte
  }

  def bigEndianToLong(bs: Array[Byte], off: Int): Long = {
    val hi = bigEndianToInt(bs, off)
    val lo = bigEndianToInt(bs, off + 4)
    ((hi & 0xffffffffL).toLong << 32) | (lo & 0xffffffffL).toLong
  }

  def longToBigEndian(n: Long, bs: Array[Byte], off: Int): Unit = {
    intToBigEndian((n >>> 32).toInt, bs, off)
    intToBigEndian((n & 0xffffffffL).toInt, bs, off + 4)
  }
}