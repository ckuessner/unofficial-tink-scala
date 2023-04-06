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

import java.security.*
import javax.crypto.{Cipher, KeyAgreement, Mac}

/**
 * Interface and its implentations to make JCE Engines have a common parent.
 *
 * <p>There's no expected reason to directly import this for users of Tink, but it might be needed
 * to implement it (say, if someone wants a new type of engine).
 *
 * @since 1.0.0
 */
object EngineWrapper {
  /** Cipher wrapper. */
  class TCipher extends EngineWrapper[Cipher] {
    @SuppressWarnings(Array("InsecureCryptoUsage"))
    @throws[GeneralSecurityException]
    override def getInstance(algorithm: String, provider: Provider): Cipher =
      if (provider == null) Cipher.getInstance(algorithm)
      else Cipher.getInstance(algorithm, provider)
  }

  /** Mac wrapper. */
  class TMac extends EngineWrapper[Mac] {
    @SuppressWarnings(Array("InsecureCryptoUsage"))
    @throws[GeneralSecurityException]
    override def getInstance(algorithm: String, provider: Provider): Mac =
      if (provider == null) Mac.getInstance(algorithm)
      else Mac.getInstance(algorithm, provider)
  }

  /** KeyPairGenerator wrapper. */
  class TKeyPairGenerator extends EngineWrapper[KeyPairGenerator] {
    @SuppressWarnings(Array("InsecureCryptoUsage"))
    @throws[GeneralSecurityException]
    override def getInstance(algorithm: String, provider: Provider): KeyPairGenerator =
      if (provider == null) KeyPairGenerator.getInstance(algorithm)
      else KeyPairGenerator.getInstance(algorithm, provider)
  }

  /** MessageDigest wrapper. */
  class TMessageDigest extends EngineWrapper[MessageDigest] {
    @SuppressWarnings(Array("InsecureCryptoUsage"))
    @throws[GeneralSecurityException]
    override def getInstance(algorithm: String, provider: Provider): MessageDigest =
      if (provider == null) MessageDigest.getInstance(algorithm)
      else MessageDigest.getInstance(algorithm, provider)
  }

  /** Signature wrapper. */
  class TSignature extends EngineWrapper[Signature] {
    @SuppressWarnings(Array("InsecureCryptoUsage"))
    @throws[GeneralSecurityException]
    override def getInstance(algorithm: String, provider: Provider): Signature =
      if (provider == null) Signature.getInstance(algorithm)
      else Signature.getInstance(algorithm, provider)
  }

  /** KeyFactory wrapper. */
  class TKeyFactory extends EngineWrapper[KeyFactory] {
    @SuppressWarnings(Array("InsecureCryptoUsage"))
    @throws[GeneralSecurityException]
    override def getInstance(algorithm: String, provider: Provider): KeyFactory =
      if (provider == null) KeyFactory.getInstance(algorithm)
      else KeyFactory.getInstance(algorithm, provider)
  }

  /** KeyAgreement wrapper. */
  class TKeyAgreement extends EngineWrapper[KeyAgreement] {
    @SuppressWarnings(Array("InsecureCryptoUsage"))
    @throws[GeneralSecurityException]
    override def getInstance(algorithm: String, provider: Provider): KeyAgreement =
      if (provider == null) KeyAgreement.getInstance(algorithm)
      else KeyAgreement.getInstance(algorithm, provider)
  }
}

trait EngineWrapper[T] {
  /** Should call T.getInstance(...). */
  @throws[GeneralSecurityException]
  def getInstance(algorithm: String, provider: Provider): T
}
