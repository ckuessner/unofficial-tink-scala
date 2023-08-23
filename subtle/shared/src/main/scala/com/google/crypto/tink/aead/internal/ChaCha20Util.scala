// Copyright 2021 Google LLC
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
package com.google.crypto.tink.aead.internal

import java.nio.{ByteBuffer, ByteOrder, IntBuffer}

/** Internal utility methods for {X}ChaCha20 implementations. */
object ChaCha20Util {
  private[internal] val BLOCK_SIZE_IN_INTS = 16
  private[internal] val KEY_SIZE_IN_INTS = 8
  private[internal] val BLOCK_SIZE_IN_BYTES = BLOCK_SIZE_IN_INTS * 4
  private[internal] val KEY_SIZE_IN_BYTES = KEY_SIZE_IN_INTS * 4

  // First four words of the initial state (in little-endian order):
  // 0x61707865, 0x3320646e, 0x79622d32, 0x6b206574.
  // See also https://datatracker.ietf.org/doc/html/rfc7539#section-2.3.
  private val SIGMA = toIntArray(
    Array[Byte](
      'e', 'x', 'p', 'a', 'n', 'd', ' ', '3', '2', '-', 'b', 'y', 't', 'e', ' ', 'k'
    )
  )

  /**
   * Sets the first 12 words of the initial state as described in
   * https://datatracker.ietf.org/doc/html/rfc7539#section-2.3.
   */
  private[internal] def setSigmaAndKey(state: Array[Int], key: Array[Int]): Unit = {
    System.arraycopy(SIGMA, 0, state, 0, SIGMA.length) // 4 words
    System.arraycopy(key, 0, state, SIGMA.length, KEY_SIZE_IN_INTS) // 8 words
  }

  /**
   * Computes the 20 ChaCha rounds as described in
   * https://datatracker.ietf.org/doc/html/rfc7539#section-2.3.
   */
  private[internal] def shuffleState(state: Array[Int]): Unit = {
    for (i <- 0 until 10) {
      quarterRound(state, 0, 4, 8, 12)
      quarterRound(state, 1, 5, 9, 13)
      quarterRound(state, 2, 6, 10, 14)
      quarterRound(state, 3, 7, 11, 15)
      quarterRound(state, 0, 5, 10, 15)
      quarterRound(state, 1, 6, 11, 12)
      quarterRound(state, 2, 7, 8, 13)
      quarterRound(state, 3, 4, 9, 14)
    }
  }

  /**
   * Computes the ChaCha quarter round as described in
   * https://datatracker.ietf.org/doc/html/rfc7539#section-2.1.
   */
  private[internal] def quarterRound(x: Array[Int], a: Int, b: Int, c: Int, d: Int): Unit = {
    x(a) += x(b)
    x(d) = rotateLeft(x(d) ^ x(a), 16)
    x(c) += x(d)
    x(b) = rotateLeft(x(b) ^ x(c), 12)
    x(a) += x(b)
    x(d) = rotateLeft(x(d) ^ x(a), 8)
    x(c) += x(d)
    x(b) = rotateLeft(x(b) ^ x(c), 7)
  }

  /** Converts {@code input} byte array to an int array */
  private[internal] def toIntArray(input: Array[Byte]) = {
    val intBuffer: IntBuffer = ByteBuffer.wrap(input).order(ByteOrder.LITTLE_ENDIAN).asIntBuffer
    val ret = new Array[Int](intBuffer.remaining)
    intBuffer.get(ret)
    ret
  }

  private def rotateLeft(x: Int, y: Int) = (x << y) | (x >>> -y)
}