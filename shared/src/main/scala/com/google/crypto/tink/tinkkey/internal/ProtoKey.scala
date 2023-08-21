// Copyright 2020 Google LLC
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
package com.google.crypto.tink.tinkkey.internal

import com.google.crypto.tink.KeyTemplate
import com.google.crypto.tink.KeyTemplate.OutputPrefixType
import com.google.crypto.tink.proto.KeyData
import com.google.crypto.tink.tinkkey.TinkKey

/**
 * Wraps the proto {@code KeyData} as an implementation of a {@code TinkKey}. The underlying {@code
 * KeyData} determines whether this ProtoKey has a secret.
 *
 * <p>ProtoKey is not intended for use outside of the Tink project.
 */
//@Immutable
object ProtoKey {
  private def isSecret(keyData: KeyData) = (keyData.getKeyMaterialType eq KeyData.KeyMaterialType.UNKNOWN_KEYMATERIAL) || (keyData.getKeyMaterialType eq KeyData.KeyMaterialType.SYMMETRIC) || (keyData.getKeyMaterialType eq KeyData.KeyMaterialType.ASYMMETRIC_PRIVATE)
}

final class ProtoKey(private val keyData: KeyData, private val outputPrefixType: KeyTemplate.OutputPrefixType) extends TinkKey {
/**
 * Constructs a ProtoKey with {@code hasSecret()} returning true if the input {@code KeyData} has
 * key material of type UNKNOWN_KEYMATERIAL, SYMMETRIC, or ASYMMETRIC_PRIVATE.
 */
  override def hasSecret: Boolean = ProtoKey.isSecret(keyData)

  def getProtoKey: KeyData = keyData

  def getOutputPrefixType: KeyTemplate.OutputPrefixType = outputPrefixType

  /**
   * @throws UnsupportedOperationException There is currently no direct way of getting a {@code
   *                                       KeyTemplate} from {@code KeyData}.
   */
  override def getKeyTemplate = throw new UnsupportedOperationException
}