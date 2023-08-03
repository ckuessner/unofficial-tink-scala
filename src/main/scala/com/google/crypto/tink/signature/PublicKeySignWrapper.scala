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
package com.google.crypto.tink.signature

import com.google.crypto.tink.proto.OutputPrefixType
import com.google.crypto.tink.subtle.Bytes
import com.google.crypto.tink.{PrimitiveSet, PrimitiveWrapper, PublicKeySign, Registry}

import java.security.GeneralSecurityException

/**
 * The implementation of {@code PrimitiveWrapper<PublicKeySign>}.
 *
 * <p>The returned primitive works with a keyset (rather than a single key). To sign a message, it
 * uses the primary key in the keyset, and prepends to the signature a certain prefix associated
 * with the primary key.
 */
object PublicKeySignWrapper {
  private val FORMAT_VERSION = Array[Byte](0)
  private val WRAPPER = new PublicKeySignWrapper

  private class WrappedPublicKeySign(private val primitives: PrimitiveSet[PublicKeySign]) extends PublicKeySign {
    @throws[GeneralSecurityException]
    override def sign(data: Array[Byte]): Array[Byte] = {
      var data2 = data
      if (primitives.getPrimary.get.getOutputPrefixType.equals(OutputPrefixType.LEGACY)) {
        data2 = Bytes.concat(data, FORMAT_VERSION)
      }
      try {
        val output = Bytes.concat(primitives.getPrimary.get.getIdentifier, primitives.getPrimary.get.getPrimitive.sign(data2))
        output
      } catch {
        case e: GeneralSecurityException =>
          throw e
      }
    }
  }

  /**
   * Register the wrapper within the registry.
   *
   * <p>This is required for calls to {@link Keyset.getPrimitive} with a {@link PublicKeySign}
   * argument.
   */
  @throws[GeneralSecurityException]
  def register(): Unit = {
    Registry.registerPrimitiveWrapper(WRAPPER)
  }
}

class PublicKeySignWrapper private[signature] extends PrimitiveWrapper[PublicKeySign, PublicKeySign] {
  override def wrap(primitives: PrimitiveSet[PublicKeySign]) = new PublicKeySignWrapper.WrappedPublicKeySign(primitives)

  override def getPrimitiveClass: Class[PublicKeySign] = classOf[PublicKeySign]

  override def getInputPrimitiveClass: Class[PublicKeySign] = classOf[PublicKeySign]
}