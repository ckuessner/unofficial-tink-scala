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

import com.google.crypto.tink.PublicKeySign

import java.security.GeneralSecurityException
import java.util

/**
 * Ed25519 signing.
 *
 * <h3>Usage</h3>
 *
 * <pre>{@code
 * Ed25519Sign.KeyPair keyPair = Ed25519Sign.KeyPair.newKeyPair();
 * // securely store keyPair and share keyPair.getPublicKey()
 * Ed25519Sign signer = new Ed25519Sign(keyPair.getPrivateKey());
 * byte[] signature = signer.sign(message);
 * }</pre>
 *
 * @since 1.1.0
 */
object Ed25519Sign {
  val SECRET_KEY_LEN: Int = Field25519.FIELD_LEN

  /** Defines the KeyPair consisting of a private key and its corresponding public key. */
  object KeyPair {
    /** Returns a new <publicKey, privateKey> KeyPair. */
    @throws[GeneralSecurityException]
    def newKeyPair: Ed25519Sign.KeyPair = newKeyPairFromSeed(Random.randBytes(Field25519.FIELD_LEN))

    /** Returns a new <publicKey, privateKey> KeyPair generated from a seed. */
    @throws[GeneralSecurityException]
    def newKeyPairFromSeed(secretSeed: Array[Byte]): Ed25519Sign.KeyPair = {
      if (secretSeed.length != Field25519.FIELD_LEN) throw new IllegalArgumentException(String.format("Given secret seed length is not %s", Field25519.FIELD_LEN))
      val privateKey = secretSeed
      val publicKey = Ed25519.scalarMultWithBaseToBytes(Ed25519.getHashedScalar(privateKey))
      new Ed25519Sign.KeyPair(publicKey, privateKey)
    }
  }

  final class KeyPair private(private val publicKey: Array[Byte], private val privateKey: Array[Byte]) {
    def getPublicKey: Array[Byte] = util.Arrays.copyOf(publicKey, publicKey.length)

    def getPrivateKey: Array[Byte] = util.Arrays.copyOf(privateKey, privateKey.length)
  }
}


/**
 * Constructs a Ed25519Sign with the {@code privateKey}.
 *
 * @param privateKey 32-byte random sequence.
 * @throws GeneralSecurityException if there is no SHA-512 algorithm defined in
 *                                  {@link EngineFactory}.MESSAGE_DIGEST.
 */
final class Ed25519Sign @throws[GeneralSecurityException](privateKey: Array[Byte]) extends PublicKeySign {
  if (privateKey.length != Ed25519Sign.SECRET_KEY_LEN) {
    throw new IllegalArgumentException(s"Given private key's length is not ${Ed25519Sign.SECRET_KEY_LEN}")
  }

  private val hashedPrivateKey: Array[Byte] = Ed25519.getHashedScalar(privateKey)
  private val publicKey: Array[Byte] = Ed25519.scalarMultWithBaseToBytes(this.hashedPrivateKey)

  @throws[GeneralSecurityException]
  override def sign(data: Array[Byte]): Array[Byte] = Ed25519.sign(data, publicKey, hashedPrivateKey)
}