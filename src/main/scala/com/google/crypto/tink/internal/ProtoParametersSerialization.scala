// Copyright 2022 Google LLC
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
package com.google.crypto.tink.internal

import com.google.crypto.tink.internal.Util.toBytesFromPrintableAscii
import com.google.crypto.tink.Parameters
import com.google.crypto.tink.aead.ChaCha20Poly1305Parameters
import com.google.crypto.tink.aead.ChaCha20Poly1305ProtoSerialization
import com.google.crypto.tink.aead.XChaCha20Poly1305Parameters
import com.google.crypto.tink.aead.XChaCha20Poly1305ProtoSerialization
import com.google.crypto.tink.proto.KeyTemplate
import com.google.crypto.tink.proto.OutputPrefixType
import com.google.crypto.tink.signature.Ed25519Parameters
import com.google.crypto.tink.signature.Ed25519ProtoSerialization
import com.google.crypto.tink.util.Bytes
import java.security.GeneralSecurityException

/**
 * Represents a {@code Parameters} object serialized with binary protobuf Serialization.
 *
 * <p>{@code ProtoParametersSerialization} objects fully describe a {@code Parameters} object, but
 * tailored for protocol buffer serialization.
 */
//@Immutable
object ProtoParametersSerialization {
  /** Creates a new {@code ProtoParametersSerialization} object from the individual parts. */
    def create(typeUrl: String, outputPrefixType: OutputPrefixType): ProtoParametersSerialization = create(KeyTemplate.newBuilder.setTypeUrl(typeUrl).setOutputPrefixType(outputPrefixType).build)

    /** Creates a new {@code ProtoParametersSerialization} object. */
    def create(keyTemplate: KeyTemplate) = new ProtoParametersSerialization(keyTemplate)
}

final class ProtoParametersSerialization private(private val keyTemplate: KeyTemplate) extends Serialization {
  this.objectIdentifier = toBytesFromPrintableAscii(keyTemplate.getTypeUrl)
  final private var objectIdentifier: Bytes = null

  @throws[GeneralSecurityException]
  def toParametersPojo: Parameters = {
    val outputPrefixType = keyTemplate.getOutputPrefixType
    if ("type.googleapis.com/google.crypto.tink.XChaCha20Poly1305Key" == keyTemplate.getTypeUrl) {
      val variant = XChaCha20Poly1305ProtoSerialization.toVariant(outputPrefixType)
      XChaCha20Poly1305Parameters.create(variant)
    }
    else if ("type.googleapis.com/google.crypto.tink.ChaCha20Poly1305Key" == keyTemplate.getTypeUrl) {
      val variant = ChaCha20Poly1305ProtoSerialization.toVariant(outputPrefixType)
      ChaCha20Poly1305Parameters.create(variant)
    }
    else if ("type.googleapis.com/google.crypto.tink.Ed25519PrivateKey" == keyTemplate.typeUrl) {
      val variant = Ed25519ProtoSerialization.toVariant(outputPrefixType)
      Ed25519Parameters.create(variant)
    }
    else throw new GeneralSecurityException("Cannot create parameters POJO for " + keyTemplate.getTypeUrl)
  }

  /** The contents of the field value in the message com.google.crypto.tink.proto.KeyData. */
  def getKeyTemplate: KeyTemplate = keyTemplate

  /** The typeUrl. */
  override def getObjectIdentifier: Bytes = objectIdentifier
}