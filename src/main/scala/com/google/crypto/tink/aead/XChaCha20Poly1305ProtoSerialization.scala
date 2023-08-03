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
import com.google.crypto.tink.internal.{KeyParser, KeySerializer, ProtoKeySerialization, ProtoParametersSerialization}
import com.google.crypto.tink.proto.KeyData.KeyMaterialType
import com.google.crypto.tink.proto.{KeyTemplate, OutputPrefixType}
import com.google.crypto.tink.util.{Bytes, SecretBytes}
import com.google.crypto.tink.{AccessesPartialKey, SecretKeyAccess, proto}
import com.google.protobuf.ByteString

import java.security.GeneralSecurityException

/**
 * Methods to serialize and parse [[XChaCha20Poly1305Key]] objects and [[ XChaCha20Poly1305Parameters]] objects
 */
@AccessesPartialKey
private[tink] object XChaCha20Poly1305ProtoSerialization {
  private val TYPE_URL = "type.googleapis.com/google.crypto.tink.XChaCha20Poly1305Key"
  private val TYPE_URL_BYTES = toBytesFromPrintableAscii(TYPE_URL)
  val KEY_SERIALIZER: KeySerializer[XChaCha20Poly1305Key, ProtoKeySerialization] = KeySerializer.create(XChaCha20Poly1305ProtoSerialization.serializeKey, classOf[XChaCha20Poly1305Key], classOf[ProtoKeySerialization])
  val KEY_PARSER: KeyParser[ProtoKeySerialization] = KeyParser.create(XChaCha20Poly1305ProtoSerialization.parseKey, TYPE_URL_BYTES, classOf[ProtoKeySerialization])

  @throws[GeneralSecurityException]
  private def toProtoOutputPrefixType(variant: XChaCha20Poly1305Parameters.Variant): OutputPrefixType = {
    if (XChaCha20Poly1305Parameters.Variant.TINK == variant) return OutputPrefixType.TINK
    if (XChaCha20Poly1305Parameters.Variant.CRUNCHY == variant) return OutputPrefixType.CRUNCHY
    if (XChaCha20Poly1305Parameters.Variant.NO_PREFIX == variant) return OutputPrefixType.RAW
    throw new GeneralSecurityException("Unable to serialize variant: " + variant)
  }

  @throws[GeneralSecurityException]
  def toVariant(outputPrefixType: OutputPrefixType): XChaCha20Poly1305Parameters.Variant = outputPrefixType match {
    case OutputPrefixType.TINK => XChaCha20Poly1305Parameters.Variant.TINK
    case OutputPrefixType.CRUNCHY => XChaCha20Poly1305Parameters.Variant.CRUNCHY
    case OutputPrefixType.LEGACY => // Parse LEGACY prefix to CRUNCHY, since they act the same for this type of key
      XChaCha20Poly1305Parameters.Variant.CRUNCHY
    case OutputPrefixType.RAW => XChaCha20Poly1305Parameters.Variant.NO_PREFIX
    case _ => throw new GeneralSecurityException("Unable to parse OutputPrefixType: " + outputPrefixType)
  }

  @throws[GeneralSecurityException]
  def serializeParameters(parameters: XChaCha20Poly1305Parameters): ProtoParametersSerialization =
    ProtoParametersSerialization.create(
      KeyTemplate.newBuilder.setTypeUrl(TYPE_URL)
        .setOutputPrefixType(toProtoOutputPrefixType(parameters.getVariant)).build
    )

  @throws[GeneralSecurityException]
  def serializeKey(key: XChaCha20Poly1305Key, access: SecretKeyAccess): ProtoKeySerialization =
    ProtoKeySerialization.create(
      TYPE_URL,
      proto.XChaCha20Poly1305Key.newBuilder.setKeyValue(ByteString.copyFrom(key.getKeyBytes.toByteArray(SecretKeyAccess.requireAccess(access)))).build,
      KeyMaterialType.SYMMETRIC,
      toProtoOutputPrefixType(key.getParameters.getVariant),
      key.getIdRequirement
    )

  @throws[GeneralSecurityException]
  def parseParameters(serialization: ProtoParametersSerialization): XChaCha20Poly1305Parameters = {
    if (!(serialization.getKeyTemplate.getTypeUrl == TYPE_URL)) throw new IllegalArgumentException("Wrong type URL in call to XChaCha20Poly1305Parameters.parseParameters: " + serialization.getKeyTemplate.getTypeUrl)
    XChaCha20Poly1305Parameters.create(toVariant(serialization.getKeyTemplate.getOutputPrefixType))
  }

  @SuppressWarnings(Array("UnusedException"))
  @throws[GeneralSecurityException]
  def parseKey(serialization: ProtoKeySerialization, access: SecretKeyAccess): XChaCha20Poly1305Key = {
    if (!(serialization.getTypeUrl == TYPE_URL)) throw new IllegalArgumentException("Wrong type URL in call to XChaCha20Poly1305Parameters.parseParameters")
    serialization.getValue match {
      case protoKey: proto.XChaCha20Poly1305Key =>
        if (protoKey.keyValue == null || protoKey.keyValue.size != 32) {
          throw new GeneralSecurityException("Parsing XChaCha20Poly1305Key failed")
        }
        XChaCha20Poly1305Key.create(
          toVariant(serialization.getOutputPrefixType),
          SecretBytes.copyFrom(protoKey.getKeyValue.toByteArray, SecretKeyAccess.requireAccess(access)),
          serialization.getIdRequirement
        )
      case _ => throw new GeneralSecurityException("Parsing XChaCha20Poly1305Key failed")
    }
  }
}