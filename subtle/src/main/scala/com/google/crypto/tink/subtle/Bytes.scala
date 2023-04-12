// Copyright 2017 Google Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
////////////////////////////////////////////////////////////////////////////////
package com.google.crypto.tink.subtle

import java.nio.ByteBuffer
import java.security.{GeneralSecurityException, MessageDigest}
import java.util
import scala.annotation.varargs

/**
 * Helper methods that deal with byte arrays.
 *
 * @since 1.0.0
 */
object Bytes {
  /**
   * Best effort fix-timing array comparison.
   *
   * @return true if two arrays are equal.
   */
  def equal(x: Array[Byte], y: Array[Byte]): Boolean = MessageDigest.isEqual(x, y)

  /**
   * Returns the concatenation of the input arrays in a single array. For example, {@code concat(new
   * byte[] {a, b}, new byte[] {}, new byte[] {c}} returns the array {@code {a, b, c}}.
   *
   * @return a single array containing all the values from the source arrays, in order
   */
  @throws[GeneralSecurityException]
  @varargs def concat(chunks: Array[Byte]*): Array[Byte] = {
    var length: Int = 0
    for (chunk <- chunks) {
      if (length > Integer.MAX_VALUE - chunk.length) throw new GeneralSecurityException("exceeded size limit")
      length += chunk.length
    }
    val res = new Array[Byte](length)
    var pos = 0
    for (chunk <- chunks) {
      System.arraycopy(chunk, 0, res, pos, chunk.length)
      pos += chunk.length
    }
    res
  }

  // TODO: Remove after conversion
  def concat(chunk1: Array[Byte], chunk2: Array[Byte]): Array[Byte] = {
    var resultLength: Long = chunk1.length
    resultLength += chunk2.length
    if (resultLength > Integer.MAX_VALUE) throw GeneralSecurityException("exceeded size limit")

    val res = new Array[Byte](resultLength.toInt)
    System.arraycopy(chunk1, 0, res, 0, chunk1.length)
    System.arraycopy(chunk2, 0, res, chunk1.length, chunk2.length)

    res
  }

  /**
   * Computes the xor of two byte arrays, specifying offsets and the length to xor.
   *
   * @return a new byte[] of length len.
   */
  def xor(x: Array[Byte], offsetX: Int, y: Array[Byte], offsetY: Int, len: Int): Array[Byte] = {
    if (len < 0 || x.length - len < offsetX || y.length - len < offsetY) throw new IllegalArgumentException("That combination of buffers, offsets and length to xor result in out-of-bond accesses.")
    val res = new Array[Byte](len)
    for (i <- 0 until len) {
      res(i) = (x(i + offsetX) ^ y(i + offsetY)).toByte
    }
    res
  }

  /**
   * Computes the xor of two byte buffers, specifying the length to xor, and
   * stores the result to {@code output}.
   *
   * @return a new byte[] of length len.
   */
  def xor(output: ByteBuffer, x: ByteBuffer, y: ByteBuffer, len: Int): Unit = {
    if (len < 0 || x.remaining < len || y.remaining < len || output.remaining < len) throw new IllegalArgumentException("That combination of buffers, offsets and length to xor result in out-of-bond accesses.")
    for (i <- 0 until len) {
      output.put((x.get ^ y.get).toByte)
    }
  }

  /**
   * Computes the xor of two byte arrays of equal size.
   *
   * @return a new byte[] of length x.length.
   */
  def xor(x: Array[Byte], y: Array[Byte]): Array[Byte] = {
    if (x.length != y.length) throw new IllegalArgumentException("The lengths of x and y should match.")
    xor(x, 0, y, 0, x.length)
  }

  /**
   * xors b to the end of a.
   *
   * @return a new byte[] of length x.length.
   */
  def xorEnd(a: Array[Byte], b: Array[Byte]): Array[Byte] = {
    if (a.length < b.length) throw new IllegalArgumentException("xorEnd requires a.length >= b.length")
    val paddingLength = a.length - b.length
    val res = util.Arrays.copyOf(a, a.length)
    for (i <- b.indices) {
      res(paddingLength + i) = (res(paddingLength + i) ^ b(i)).toByte
    }
    res
  }

  /**
   * Transforms a passed value to a LSB first byte array with the size of the specified capacity
   *
   * @param capacity size of the resulting byte array
   * @param value    that should be represented as a byte array
   */
  // TODO(thaidn): add checks for boundary conditions/overflows.
  def intToByteArray(capacity: Int, value: Int): Array[Byte] = {
    val result = new Array[Byte](capacity)
    for (i <- 0 until capacity) {
      result(i) = ((value >> (8 * i)) & 0xFF).toByte
    }
    result
  }

  /**
   * Transforms a passed LSB first byte array to an int
   *
   * @param bytes that should be transformed to a byte array
   */
  def byteArrayToInt(bytes: Array[Byte]): Int = byteArrayToInt(bytes, bytes.length)

  /**
   * Transforms a passed LSB first byte array to an int
   *
   * @param bytes  that should be transformed to a byte array
   * @param length amount of the passed {@code bytes} that should be transformed
   */
  def byteArrayToInt(bytes: Array[Byte], length: Int): Int = byteArrayToInt(bytes, 0, length)

  /**
   * Transforms a passed LSB first byte array to an int
   *
   * @param bytes  that should be transformed to a byte array
   * @param offset start index to start the transformation
   * @param length amount of the passed {@code bytes} that should be transformed
   */
  def byteArrayToInt(bytes: Array[Byte], offset: Int, length: Int): Int = {
    var value = 0
    for (i <- 0 until length) {
      value += (bytes(i + offset) & 0xFF) << (i * 8)
    }
    value
  }
}