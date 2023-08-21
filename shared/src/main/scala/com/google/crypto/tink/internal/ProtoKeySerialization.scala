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
import com.google.crypto.tink.proto.KeyData.KeyMaterialType
import com.google.crypto.tink.proto.{KeyData, KeyProto, OutputPrefixType}
import com.google.crypto.tink.util.Bytes

import java.security.GeneralSecurityException

/**
 * * Represents a {@code Key} object serialized with binary protobuf Serialization.
 *
 * <p>{@code ProtoKeySerialization} objects fully describe a {@code Key} object, but tailored for
 * protocol buffer serialization.
 */
//@Immutable
object ProtoKeySerialization {
  @throws[GeneralSecurityException]
  def create(typeUrl: String, value: KeyProto, keyMaterialType: KeyData.KeyMaterialType, outputPrefixType: OutputPrefixType, idRequirement: Option[Int]): ProtoKeySerialization = {
    if (outputPrefixType eq OutputPrefixType.RAW) {
      if (idRequirement != null && idRequirement.isDefined) throw new GeneralSecurityException("Keys with output prefix type raw should not have an id requirement.")
    } else if (idRequirement == null || idRequirement.isEmpty) throw new GeneralSecurityException("Keys with output prefix type different from raw should have an id requirement.")
    new ProtoKeySerialization(typeUrl, value, keyMaterialType, outputPrefixType, idRequirement)
  }

  def create(typeUrl: String, value: KeyProto, keyMaterialType: KeyData.KeyMaterialType, outputPrefixType: OutputPrefixType, idRequirement: Int): ProtoKeySerialization = {
    create(typeUrl, value, keyMaterialType, outputPrefixType, Some(idRequirement))
  }
}

final class ProtoKeySerialization private(private val typeUrl: String,
                                          private val value: KeyProto,
                                          private val keyMaterialType: KeyData.KeyMaterialType,
                                          private val outputPrefixType: OutputPrefixType,
                                          private val idRequirement: Option[Int]) extends Serialization {

  private val objectIdentifier: Bytes = toBytesFromPrintableAscii(typeUrl)

  /** The contents of the field value in the message com.google.crypto.tink.proto.KeyData. */
  def getValue: KeyProto = value

  /**
   * The contents of the field key_material_type in the message
   * com.google.crypto.tink.proto.KeyData.
   */
  def getKeyMaterialType: KeyData.KeyMaterialType = keyMaterialType

  /**
   * The contents of the field output_prefix_type in the message
   * com.google.crypto.tink.proto.Keyset.Key.
   */
  def getOutputPrefixType: OutputPrefixType = outputPrefixType

  /**
   * The id requirement of this key. Guaranteed to be None if getOutputPrefixType == RAW, otherwise
   * Some(ID this key has to have).
   */
  def getIdRequirement: Option[Int] = idRequirement

  /**
   * The object identifier.
   *
   * <p>This is the UTF8 encoding of the result of "getTypeUrl".
   */
  override def getObjectIdentifier: Bytes = objectIdentifier

  /** The typeUrl. */
  def getTypeUrl: String = typeUrl
}