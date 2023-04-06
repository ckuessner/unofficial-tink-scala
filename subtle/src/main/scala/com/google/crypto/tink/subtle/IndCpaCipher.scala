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

import java.security.GeneralSecurityException

/**
 * This interface for symmetric key ciphers that are indistinguishable against chosen-plaintext
 * attacks.
 *
 * <p>Said primitives do not provide authentication, thus should not be used directly, but only to
 * construct safer primitives such as {@link com.google.crypto.tink.Aead}.
 *
 * @since 1.0.0
 */
trait IndCpaCipher {
  /**
   * Encrypts {@code plaintext}. The resulting ciphertext is indistinguishable under
   * chosen-plaintext attack. However, it does not have integrity protection.
   *
   * @return the resulting ciphertext.
   */
  @throws[GeneralSecurityException]
  def encrypt(plaintext: Array[Byte]): Array[Byte]

  /**
   * Decrypts {@code ciphertext}.
   *
   * @return the resulting plaintext.
   */
  @throws[GeneralSecurityException]
  def decrypt(ciphertext: Array[Byte]): Array[Byte]
}