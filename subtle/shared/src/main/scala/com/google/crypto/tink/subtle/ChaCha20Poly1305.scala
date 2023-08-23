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

import com.google.crypto.tink.Aead
import com.google.crypto.tink.aead.internal.{InsecureNonceChaCha20Poly1305, Poly1305}

import java.nio.ByteBuffer
import java.security.GeneralSecurityException
import java.util

/**
 * ChaCha20Poly1305 AEAD construction, as described in <a
 * href="https://tools.ietf.org/html/rfc8439#section-2.8">RFC 8439, section 2.8</a>.
 *
 * @since 1.1.0
 */
final class ChaCha20Poly1305 @throws[GeneralSecurityException](key: Array[Byte]) extends Aead {
  private val cipher: InsecureNonceChaCha20Poly1305 = new InsecureNonceChaCha20Poly1305(key)

  @throws[GeneralSecurityException]
  override def encrypt(plaintext: Array[Byte], associatedData: Array[Byte]): Array[Byte] = {
    val output = ByteBuffer.allocate(ChaCha20.NONCE_LENGTH_IN_BYTES + plaintext.length + Poly1305.MAC_TAG_SIZE_IN_BYTES)
    val nonce = Random.randBytes(ChaCha20.NONCE_LENGTH_IN_BYTES)
    output.put(nonce) // Prepend nonce to ciphertext output.
    cipher.encrypt(output, nonce, plaintext, associatedData)
    output.array
  }

  @throws[GeneralSecurityException]
  override def decrypt(ciphertext: Array[Byte], associatedData: Array[Byte]): Array[Byte] = {
    if (ciphertext.length < ChaCha20.NONCE_LENGTH_IN_BYTES + Poly1305.MAC_TAG_SIZE_IN_BYTES) {
      throw new GeneralSecurityException("ciphertext too short")
    }
    val nonce = util.Arrays.copyOf(ciphertext, ChaCha20.NONCE_LENGTH_IN_BYTES)
    val rawCiphertext = ByteBuffer.wrap(
      ciphertext,
      ChaCha20.NONCE_LENGTH_IN_BYTES,
      ciphertext.length - ChaCha20.NONCE_LENGTH_IN_BYTES)
    cipher.decrypt(rawCiphertext, nonce, associatedData)
  }
}