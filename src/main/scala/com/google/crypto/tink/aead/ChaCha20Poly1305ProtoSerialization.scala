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

import com.google.crypto.tink.internal.Util.toBytesFromPrintableAscii
import com.google.crypto.tink.{AccessesPartialKey, SecretKeyAccess, proto}
import com.google.crypto.tink.internal.KeyParser
import com.google.crypto.tink.internal.KeySerializer
import com.google.crypto.tink.internal.ProtoKeySerialization
import com.google.crypto.tink.proto.KeyData.KeyMaterialType
import com.google.crypto.tink.proto.KeyProto
import com.google.crypto.tink.proto.OutputPrefixType
import com.google.crypto.tink.util.Bytes
import com.google.crypto.tink.util.SecretBytes
import com.google.protobuf.ByteString

import java.security.GeneralSecurityException

/**
 * Methods to serialize and parse [[ChaCha20Poly1305Key]] objects and [[ChaCha20Poly1305Parameters]] objects
 */
@AccessesPartialKey
private[tink] object ChaCha20Poly1305ProtoSerialization {
  private[aead] val TYPE_URL = "type.googleapis.com/google.crypto.tink.ChaCha20Poly1305Key"
  private val TYPE_URL_BYTES = toBytesFromPrintableAscii(TYPE_URL)
  val KEY_SERIALIZER: KeySerializer[ChaCha20Poly1305Key, ProtoKeySerialization] = KeySerializer.create(ChaCha20Poly1305ProtoSerialization.serializeKey, classOf[ChaCha20Poly1305Key], classOf[ProtoKeySerialization])
  val KEY_PARSER: KeyParser[ProtoKeySerialization] = KeyParser.create(ChaCha20Poly1305ProtoSerialization.parseKey, TYPE_URL_BYTES, classOf[ProtoKeySerialization])

  @throws[GeneralSecurityException]
  private def toProtoOutputPrefixType(variant: ChaCha20Poly1305Parameters.Variant): OutputPrefixType = {
    if (ChaCha20Poly1305Parameters.Variant.TINK == variant) return OutputPrefixType.TINK
    if (ChaCha20Poly1305Parameters.Variant.CRUNCHY == variant) return OutputPrefixType.CRUNCHY
    if (ChaCha20Poly1305Parameters.Variant.NO_PREFIX == variant) return OutputPrefixType.RAW
    throw new GeneralSecurityException("Unable to serialize variant: " + variant)
  }

  @throws[GeneralSecurityException]
  def toVariant(outputPrefixType: OutputPrefixType): ChaCha20Poly1305Parameters.Variant = outputPrefixType match {
    case OutputPrefixType.TINK => ChaCha20Poly1305Parameters.Variant.TINK
    case OutputPrefixType.CRUNCHY => ChaCha20Poly1305Parameters.Variant.CRUNCHY
    /** Parse LEGACY prefix to CRUNCHY, since they act the same for this type of key */
    case OutputPrefixType.LEGACY => ChaCha20Poly1305Parameters.Variant.CRUNCHY
    case OutputPrefixType.RAW => ChaCha20Poly1305Parameters.Variant.NO_PREFIX
    case _ => throw new GeneralSecurityException("Unable to parse OutputPrefixType: " + outputPrefixType)
  }

  @throws[GeneralSecurityException]
  private def serializeKey(key: ChaCha20Poly1305Key, access: SecretKeyAccess) = ProtoKeySerialization.create(
      TYPE_URL,
      proto.ChaCha20Poly1305Key.newBuilder.setKeyValue(ByteString.copyFrom(key.getKeyBytes.toByteArray(SecretKeyAccess.requireAccess(access)))).build(),
      KeyMaterialType.SYMMETRIC, toProtoOutputPrefixType(key.getParameters.getVariant),
      key.getIdRequirement
    )

  @SuppressWarnings(Array("UnusedException"))
  @throws[GeneralSecurityException]
  private def parseKey(serialization: ProtoKeySerialization, access: SecretKeyAccess) = {
    if (!(serialization.getTypeUrl == TYPE_URL)) throw new IllegalArgumentException("Wrong type URL in call to ChaCha20Poly1305Parameters.parseParameters")
    serialization.getValue match
      case protoKey: proto.ChaCha20Poly1305Key =>
        if (protoKey.keyValue == null || protoKey.keyValue.size != 32) {
          throw new GeneralSecurityException("Parsing XChaCha20Poly1305Key failed")
        }
        ChaCha20Poly1305Key.create(
          toVariant(serialization.getOutputPrefixType),
          SecretBytes.copyFrom(protoKey.getKeyValue.toByteArray, SecretKeyAccess.requireAccess(access)),
          serialization.getIdRequirement
        )
      case _ => throw new GeneralSecurityException("Parsing ChaCha20Poly1305Key failed")
  }
}