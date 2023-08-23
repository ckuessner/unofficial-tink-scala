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

/**
 * Helper methods for encode/decode hex strings.
 *
 * @since 1.0.0
 */
object Hex {
  /** Encodes a byte array to hex. */
  def encode(bytes: Array[Byte]): String = {
    val chars = "0123456789abcdef"
    val result = new StringBuilder(2 * bytes.length)
    for (b <- bytes) {
      // convert to unsigned
      val `val` = b & 0xff
      result.append(chars.charAt(`val` / 16))
      result.append(chars.charAt(`val` % 16))
    }
    result.toString
  }

  /** Decodes a hex string to a byte array. */
  def decode(hex: String): Array[Byte] = {
    if (hex.length % 2 != 0) {
      throw new IllegalArgumentException("Expected a string of even length")
    }

    val size = hex.length / 2
    val result = new Array[Byte](size)
    for (i <- 0 until size) {
      val hi = Character.digit(hex.charAt(2 * i), 16)
      val lo = Character.digit(hex.charAt(2 * i + 1), 16)
      if ((hi == -1) || (lo == -1)) throw new IllegalArgumentException("input is not hexadecimal")
      result(i) = (16 * hi + lo).toByte
    }
    result
  }
}