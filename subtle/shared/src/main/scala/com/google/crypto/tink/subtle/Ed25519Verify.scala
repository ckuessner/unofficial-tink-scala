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

import com.google.crypto.tink.PublicKeyVerify
import com.google.crypto.tink.util.Bytes

import java.security.GeneralSecurityException

/**
 * Ed25519 verifying.
 *
 * <h3>Usage</h3>
 *
 * <pre>{@code
 * // get the publicKey from the other party.
 * Ed25519Verify verifier = new Ed25519Verify(publicKey);
 * try {
 * verifier.verify(signature, message);
 * } catch (GeneralSecurityException e) {
 * // all the rest of security exceptions.
 * }
 * }</pre>
 *
 * @since 1.1.0
 */
object Ed25519Verify {
  val PUBLIC_KEY_LEN: Int = Field25519.FIELD_LEN
  val SIGNATURE_LEN: Int = Field25519.FIELD_LEN * 2
}

final class Ed25519Verify(publicKeyBytes: Array[Byte]) extends PublicKeyVerify {
  if (publicKeyBytes.length != Ed25519Verify.PUBLIC_KEY_LEN) {
    throw new IllegalArgumentException(s"Given public key's length is not ${Ed25519Verify.PUBLIC_KEY_LEN}.")
  }

  private val publicKey: Bytes = Bytes.copyFrom(publicKeyBytes)

  @throws[GeneralSecurityException]
  override def verify(signature: Array[Byte], data: Array[Byte]): Unit = {
    if (signature.length != Ed25519Verify.SIGNATURE_LEN) {
      throw new GeneralSecurityException(s"The length of the signature is not ${Ed25519Verify.SIGNATURE_LEN}.")
    }

    if (!Ed25519.verify(data, signature, publicKey.toByteArray)) {
      throw new GeneralSecurityException("Signature check failed.")
    }
  }
}