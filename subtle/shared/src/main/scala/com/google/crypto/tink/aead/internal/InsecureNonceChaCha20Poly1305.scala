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

import java.security.{GeneralSecurityException, InvalidKeyException}

/**
 * ChaCha20Poly1305 AEAD construction, as described in <a
 * href="https://tools.ietf.org/html/rfc8439#section-2.8">RFC 8439, section 2.8</a>.
 *
 * @since 1.1.0
 */
final class InsecureNonceChaCha20Poly1305 @throws[GeneralSecurityException](key: Array[Byte]) extends InsecureNonceChaCha20Poly1305Base(key) {
  @throws[InvalidKeyException]
  override private[internal] def newChaCha20Instance(key: Array[Byte], initialCounter: Int): InsecureNonceChaCha20 = {
    new InsecureNonceChaCha20(key, initialCounter)
  }
}