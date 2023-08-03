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
package com.google.crypto.tink.aead

import com.google.crypto.tink.subtle.Bytes
import com.google.crypto.tink.{Aead, CryptoFormat, PrimitiveSet, PrimitiveWrapper, Registry}

import java.security.GeneralSecurityException
import java.util
import java.util.logging.Logger
import scala.jdk.CollectionConverters.IterableHasAsScala

/**
 * AeadWrapper is the implementation of SetWrapper for the Aead primitive.
 *
 * <p>Key rotation works as follows: each ciphertext is prefixed with the keyId. When decrypting, we
 * first try all primitives whose keyId starts with the prefix of the ciphertext. If none of these
 * succeed, we try the raw primitives. If any succeeds, we return the ciphertext, otherwise we
 * simply throw a GeneralSecurityException.
 */
object AeadWrapper {
  private val WRAPPER = new AeadWrapper

  private[AeadWrapper] class WrappedAead private[AeadWrapper](private val pSet: PrimitiveSet[Aead]) extends Aead {
    @throws[GeneralSecurityException]
    override def encrypt(plaintext: Array[Byte], associatedData: Array[Byte]): Array[Byte] = {
      Bytes.concat(
        pSet.getPrimary.get.getIdentifier,
        pSet.getPrimary.get.getPrimitive.encrypt(plaintext, associatedData)
      )
    }

    @throws[GeneralSecurityException]
    override def decrypt(ciphertext: Array[Byte], associatedData: Array[Byte]): Array[Byte] = {
      if (ciphertext.length > CryptoFormat.NON_RAW_PREFIX_SIZE) {
        val prefix = util.Arrays.copyOf(ciphertext, CryptoFormat.NON_RAW_PREFIX_SIZE)
        val ciphertextNoPrefix = util.Arrays.copyOfRange(ciphertext, CryptoFormat.NON_RAW_PREFIX_SIZE, ciphertext.length)
        val entries: List[PrimitiveSet.Entry[Aead]] = pSet.getPrimitive(prefix)

        var i = 0
        while (i < entries.size) {
          try {
            return entries(i).getPrimitive.decrypt(ciphertextNoPrefix, associatedData)
          } catch {
            case _: GeneralSecurityException =>
          }

          i += 1
        }
      }

      // Let's try all RAW keys.
      val entries = pSet.getRawPrimitives
      var i = 0
      while (i < entries.size) {
        try {
          return entries(i).getPrimitive.decrypt(ciphertext, associatedData)
        } catch {
          case _: GeneralSecurityException =>
        }

        i += 1
      }

      // nothing works.
      throw new GeneralSecurityException("decryption failed")
    }
  }

  @throws[GeneralSecurityException]
  def register(): Unit = {
    Registry.registerPrimitiveWrapper(WRAPPER)
  }
}

class AeadWrapper private[aead] extends PrimitiveWrapper[Aead, Aead] {
  @throws[GeneralSecurityException]
  override def wrap(pset: PrimitiveSet[Aead]) = new AeadWrapper.WrappedAead(pset)

  override def getPrimitiveClass: Class[Aead] = classOf[Aead]

  override def getInputPrimitiveClass: Class[Aead] = classOf[Aead]
}