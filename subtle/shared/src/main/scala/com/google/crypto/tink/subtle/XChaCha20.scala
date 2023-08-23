// Copyright 2018 Google Inc.
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

import com.google.crypto.tink.aead.internal.InsecureNonceXChaCha20

import java.nio.ByteBuffer
import java.security.{GeneralSecurityException, InvalidKeyException}
import java.util

object XChaCha20 {
  private[subtle] val NONCE_LENGTH_IN_BYTES = 24
}

/**
 * {@link XChaCha20} stream cipher based on
 * https://download.libsodium.org/doc/advanced/xchacha20.html and
 * https://tools.ietf.org/html/draft-arciszewski-xchacha-01.
 *
 * <p>This cipher is meant to be used to construct an AEAD with Poly1305.
 *
 * Constructs a new XChaCha20 cipher with the supplied {@code key}.
 *
 * @throws IllegalArgumentException when {@code key} length is not
 *                                  {@link com.google.crypto.tink.aead.internal.ChaCha20Util.KEY_SIZE_IN_BYTES}.
 */
class XChaCha20 @throws[InvalidKeyException] private[subtle](key: Array[Byte], initialCounter: Int) extends IndCpaCipher {
  final private val cipher: InsecureNonceXChaCha20 = new InsecureNonceXChaCha20(key, initialCounter)

  @throws[GeneralSecurityException]
  override def encrypt(plaintext: Array[Byte]) = {
    val output = ByteBuffer.allocate(XChaCha20.NONCE_LENGTH_IN_BYTES + plaintext.length)
    val nonce = Random.randBytes(XChaCha20.NONCE_LENGTH_IN_BYTES)
    output.put(nonce) // Prepend nonce to ciphertext output.
    cipher.encrypt(output, nonce, plaintext)
    output.array
  }

  @throws[GeneralSecurityException]
  override def decrypt(ciphertext: Array[Byte]) = {
    if (ciphertext.length < XChaCha20.NONCE_LENGTH_IN_BYTES) {
      throw new GeneralSecurityException("ciphertext too short")
    }
    val nonce = util.Arrays.copyOf(ciphertext, XChaCha20.NONCE_LENGTH_IN_BYTES)
    val rawCiphertext = ByteBuffer.wrap(ciphertext, XChaCha20.NONCE_LENGTH_IN_BYTES, ciphertext.length - XChaCha20.NONCE_LENGTH_IN_BYTES)
    cipher.decrypt(nonce, rawCiphertext)
  }
}