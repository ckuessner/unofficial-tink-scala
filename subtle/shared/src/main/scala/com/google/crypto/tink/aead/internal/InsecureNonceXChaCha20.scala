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

import java.security.InvalidKeyException
import java.util

/**
 * {@link InsecureNonceXChaCha20} stream cipher based on
 * https://download.libsodium.org/doc/advanced/xchacha20.html and
 * https://tools.ietf.org/html/draft-arciszewski-xchacha-01.
 *
 * <p>This cipher is meant to be used to construct an AEAD with Poly1305. Specifically, it is only
 * intended to be used for scenarios that require user-supplied nonces, which would be insecure if
 * the user-supplied nonce ever repeats. Therefore, most users should prefer
 * {@link com.google.crypto.tink.subtle.XChaCha20} instead, since it automatically supplies random nonce
 * inputs.
 */
object InsecureNonceXChaCha20 {
  val NONCE_SIZE_IN_BYTES = 24

  // See https://tools.ietf.org/html/draft-arciszewski-xchacha-01#section-2.2.
  private[internal] def hChaCha20(key: Array[Int], nonce: Array[Int]): Array[Int] = {
    val state = new Array[Int](ChaCha20Util.BLOCK_SIZE_IN_INTS)
    ChaCha20Util.setSigmaAndKey(state, key)
    state(12) = nonce(0)
    state(13) = nonce(1)
    state(14) = nonce(2)
    state(15) = nonce(3)
    ChaCha20Util.shuffleState(state)
    // state[0] = state[0], state[1] = state[1], state[2] = state[2], state[3] = state[3]
    state(4) = state(12)
    state(5) = state(13)
    state(6) = state(14)
    state(7) = state(15)
    util.Arrays.copyOf(state, ChaCha20Util.KEY_SIZE_IN_INTS)
  }
}

/**
 * Constructs a new InsecureNonceXChaCha20 cipher with the supplied {@code key}.
 *
 * @throws IllegalArgumentException when {@code key} length is not {@link ChaCha20Util.KEY_SIZE_IN_BYTES}.
 */
class InsecureNonceXChaCha20 @throws[InvalidKeyException](_key: Array[Byte], initialCounter: Int) extends InsecureNonceChaCha20Base(_key, initialCounter) {
  private[internal] def createInitialState(nonce: Array[Int], counter: Int): Array[Int] = {
    if (nonce.length != nonceSizeInBytes / 4) {
      throw new IllegalArgumentException(s"XChaCha20 uses 192-bit nonces, but got a ${nonce.length * 32}-bit nonce")
    }
    // Set the initial state based on
    // https://tools.ietf.org/html/draft-arciszewski-xchacha-01#section-2.3.
    val state = new Array[Int](ChaCha20Util.BLOCK_SIZE_IN_INTS)
    ChaCha20Util.setSigmaAndKey(state, InsecureNonceXChaCha20.hChaCha20(this.key, nonce))
    state(12) = counter
    state(13) = 0
    state(14) = nonce(4)
    state(15) = nonce(5)
    state
  }

  val nonceSizeInBytes: Int = InsecureNonceXChaCha20.NONCE_SIZE_IN_BYTES
}