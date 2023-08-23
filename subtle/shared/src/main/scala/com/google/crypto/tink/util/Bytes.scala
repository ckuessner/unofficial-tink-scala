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
package com.google.crypto.tink.util

import com.google.crypto.tink.subtle.Hex

import java.util

object Bytes {
  /**
   * @param data the byte array to be wrapped.
   * @return an immutable wrapper around the provided bytes.
   */
  def copyFrom(data: Array[Byte]): Bytes = {
    if (data == null) throw new NullPointerException("data must be non-null")
    copyFrom(data, 0, data.length)
  }

  /**
   * Wrap an immutable byte array over a slice of a Bytes
   *
   * @param data  the byte array to be wrapped.
   * @param start the starting index of the slice
   * @param len   the length of the slice. start + len must be less than the length of the array.
   * @return an immutable wrapper around the bytes in the slice from {@code start} to
   *         {@code start + len}
   */
  def copyFrom(data: Array[Byte], start: Int, len: Int): Bytes = {
    if (data == null) throw new NullPointerException("data must be non-null")
    new Bytes(data, start, len)
  }
}

/**
 * Immutable Wrapper around a byte array.
 *
 * <p>Wrap a bytearray so it prevents callers from modifying its contents. It does this by making a
 * copy upon initialization, and also makes a copy if the underlying bytes are requested.
 *
 * @since 1.0.0
 */
//@Immutable
final class Bytes private(buf: Array[Byte], start: Int, len: Int) {

  private val data = new Array[Byte](len)
  System.arraycopy(buf, start, data, 0, len)

  /**
   * @return a copy of the bytes wrapped by this object.
   */
  def toByteArray: Array[Byte] = {
    val result = new Array[Byte](data.length)
    System.arraycopy(data, 0, result, 0, data.length)
    result
  }

  /**
   * @return the length of the bytes wrapped by this object.
   */
  def size: Int = data.length

  override def equals(o: Any): Boolean = {
    if (!o.isInstanceOf[Bytes]) return false
    val other = o.asInstanceOf[Bytes]
    util.Arrays.equals(other.data, data)
  }

  override def hashCode: Int = util.Arrays.hashCode(data)

  override def toString: String = "Bytes(" + Hex.encode(data) + ")"
}