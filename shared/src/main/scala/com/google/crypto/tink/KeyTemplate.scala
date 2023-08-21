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
package com.google.crypto.tink

import com.google.crypto.tink.KeyTemplate.OutputPrefixType
import com.google.crypto.tink.proto.OutputPrefixType.TINK

/** A KeyTemplate specifies how to generate keys of a particular type. */
//@Immutable
object KeyTemplate {
  /**
   * Tink produces and accepts ciphertexts or signatures that consist of a prefix and a payload. The
   * payload and its format is determined entirely by the primitive, but the prefix has to be one of
   * the following 4 types:
   *
   * <ul>
   * <li>Legacy: prefix is 5 bytes, starts with \x00 and followed by a 4-byte key id that is
   * computed from the key material.
   * <li>Crunchy: prefix is 5 bytes, starts with \x00 and followed by a 4-byte key id that is
   * generated randomly.
   * <li>Tink : prefix is 5 bytes, starts with \x01 and followed by 4-byte key id that is
   * generated randomly.
   * <li>Raw : prefix is 0 byte, i.e., empty.
   * </ul>
   */
  enum OutputPrefixType extends java.lang.Enum[OutputPrefixType] {
    case TINK
    case LEGACY
    case RAW
    case CRUNCHY
  }

  private[tink] def fromProto(outputPrefixType: com.google.crypto.tink.proto.OutputPrefixType) = outputPrefixType match {
    case com.google.crypto.tink.proto.OutputPrefixType.TINK => OutputPrefixType.TINK
    case com.google.crypto.tink.proto.OutputPrefixType.LEGACY => OutputPrefixType.LEGACY
    case com.google.crypto.tink.proto.OutputPrefixType.RAW => OutputPrefixType.RAW
    case com.google.crypto.tink.proto.OutputPrefixType.CRUNCHY => OutputPrefixType.CRUNCHY
    case _ => throw new IllegalArgumentException("Unknown output prefix type")
  }

  private[tink] def toProto(outputPrefixType: KeyTemplate.OutputPrefixType): com.google.crypto.tink.proto.OutputPrefixType = {
    outputPrefixType match {
      case OutputPrefixType.TINK =>
        return com.google.crypto.tink.proto.OutputPrefixType.TINK
      case OutputPrefixType.LEGACY =>
        return com.google.crypto.tink.proto.OutputPrefixType.LEGACY
      case OutputPrefixType.RAW =>
        return com.google.crypto.tink.proto.OutputPrefixType.RAW
      case OutputPrefixType.CRUNCHY =>
        return com.google.crypto.tink.proto.OutputPrefixType.CRUNCHY
    }
    throw new IllegalArgumentException("Unknown output prefix type")
  }

  def create(typeUrl: String, outputPrefixType: KeyTemplate.OutputPrefixType) = new KeyTemplate(com.google.crypto.tink.proto.KeyTemplate.newBuilder.setTypeUrl(typeUrl).setOutputPrefixType(toProto(outputPrefixType)).build)
}

final class KeyTemplate private(private val kt: com.google.crypto.tink.proto.KeyTemplate) {
  private[tink] def getProto = kt

  def getTypeUrl: String = kt.getTypeUrl

  def getOutputPrefixType: KeyTemplate.OutputPrefixType = KeyTemplate.fromProto(kt.getOutputPrefixType)

  type OutputPrefixType = KeyTemplate.OutputPrefixType
}