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

import com.google.crypto.tink.aead.internal.InsecureNonceChaCha20
import java.nio.ByteBuffer
import java.security.{GeneralSecurityException, InvalidKeyException}
import java.util

/**
 * A stream cipher, as described in RFC 8439 https://tools.ietf.org/html/rfc8439, section 2.4.
 *
 * <p>This cipher is meant to be used to construct an AEAD with Poly1305.
 */
object ChaCha20 {
  private[subtle] val NONCE_LENGTH_IN_BYTES = 12
}

class ChaCha20 @throws[InvalidKeyException] private [subtle](key: Array[Byte], initialCounter: Int) extends IndCpaCipher {
  final private val cipher: InsecureNonceChaCha20 = new InsecureNonceChaCha20(key, initialCounter)

  @throws[GeneralSecurityException]
  override def encrypt(plaintext: Array[Byte]) = {
    val output = ByteBuffer.allocate(ChaCha20.NONCE_LENGTH_IN_BYTES + plaintext.length)
    val nonce = Random.randBytes(ChaCha20.NONCE_LENGTH_IN_BYTES)
    output.put(nonce) // Prepend nonce to ciphertext output.
    cipher.encrypt(output, nonce, plaintext)
    output.array
  }

  @throws[GeneralSecurityException]
  override def decrypt(ciphertext: Array[Byte]) = {
    if (ciphertext.length < ChaCha20.NONCE_LENGTH_IN_BYTES) throw new GeneralSecurityException("ciphertext too short")
    val nonce = util.Arrays.copyOf(ciphertext, ChaCha20.NONCE_LENGTH_IN_BYTES)
    val rawCiphertext =
      ByteBuffer.wrap(
        ciphertext, ChaCha20.NONCE_LENGTH_IN_BYTES, ciphertext.length - ChaCha20.NONCE_LENGTH_IN_BYTES)
    cipher.decrypt(nonce, rawCiphertext)
  }
}
