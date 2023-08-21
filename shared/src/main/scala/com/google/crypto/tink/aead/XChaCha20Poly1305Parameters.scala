// Copyright 2023 Google LLC
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

import com.google.crypto.tink.KeyTemplate
import com.google.crypto.tink.internal.TinkBugException
import java.util.Objects

/** Describes the parameters of an {@link XChaChaPoly1305Key}. */
object XChaCha20Poly1305Parameters {
  /**
   * Describes how the prefix is computed. For AEAD there are three main possibilities: NO_PREFIX
   * (empty prefix), TINK (prefix the ciphertext with 0x01 followed by a 4-byte key id in big endian
   * format) or CRUNCHY (prefix the ciphertext with 0x00 followed by a 4-byte key id in big endian
   * format).
   */
  //@Immutable
  object Variant {
    val TINK = new XChaCha20Poly1305Parameters.Variant("TINK")
    val CRUNCHY = new XChaCha20Poly1305Parameters.Variant("CRUNCHY")
    val NO_PREFIX = new XChaCha20Poly1305Parameters.Variant("NO_PREFIX")
  }

  final class Variant private(private val name: String) {
    override def toString: String = name
  }

  def create = new XChaCha20Poly1305Parameters(Variant.NO_PREFIX)

  def create(variant: XChaCha20Poly1305Parameters.Variant) = new XChaCha20Poly1305Parameters(variant)
}

final class XChaCha20Poly1305Parameters private(private val variant: XChaCha20Poly1305Parameters.Variant) extends AeadParameters {
  override def toKeyTemplate: KeyTemplate = {
    var outputPrefixType: KeyTemplate.OutputPrefixType = null
    if (XChaCha20Poly1305Parameters.Variant.NO_PREFIX eq variant) outputPrefixType = KeyTemplate.OutputPrefixType.RAW
    else if (XChaCha20Poly1305Parameters.Variant.CRUNCHY eq variant) outputPrefixType = KeyTemplate.OutputPrefixType.CRUNCHY
    else if (XChaCha20Poly1305Parameters.Variant.TINK eq variant) outputPrefixType = KeyTemplate.OutputPrefixType.TINK
    else throw new TinkBugException("Unknown variant in XChaCha20Poly1305Parameters")
    KeyTemplate.create("type.googleapis.com/google.crypto.tink.XChaCha20Poly1305Key", outputPrefixType)
  }

  /** Returns a variant object. */
  def getVariant: XChaCha20Poly1305Parameters.Variant = variant

  override def equals(o: Any): Boolean = {
    if (!o.isInstanceOf[XChaCha20Poly1305Parameters]) return false
    val that = o.asInstanceOf[XChaCha20Poly1305Parameters]
    that.getVariant eq getVariant
  }

  override def hashCode: Int = Objects.hashCode(variant)

  override def hasIdRequirement: Boolean = variant ne XChaCha20Poly1305Parameters.Variant.NO_PREFIX

  override def toString: String = "XChaCha20Poly1305 Parameters (variant: " + variant + ")"
}