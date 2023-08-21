// Copyright 2021 Google LLC
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

import com.google.crypto.tink.tinkkey.KeyHandle.KeyStatusType

/**
 * Util functions to facilitate conversion between the {@link KeyHandle.KeyStatusType} enum and
 * {@link KeyStatusType} proto.
 */
object KeyStatusTypeProtoConverter {
  /** Converts a {@link KeyStatusType} proto enum into a {@link KeyHandle.KeyStatusType} enum */
  def fromProto(keyStatusTypeProto: com.google.crypto.tink.proto.KeyStatusType): KeyStatusType = keyStatusTypeProto match {
    case com.google.crypto.tink.proto.KeyStatusType.ENABLED =>
      KeyStatusType.ENABLED
    case com.google.crypto.tink.proto.KeyStatusType.DISABLED =>
      KeyStatusType.DISABLED
    case com.google.crypto.tink.proto.KeyStatusType.DESTROYED =>
      KeyStatusType.DESTROYED
    case _ =>
      throw new IllegalArgumentException("Unknown key status type.")
  }

  /** Converts a {@link KeyHandle.KeyStatusType} enum into a {@link KeyStatusType} proto enum */
  def toProto(status: KeyStatusType): com.google.crypto.tink.proto.KeyStatusType = {
    status match {
      case KeyStatusType.ENABLED =>
        return com.google.crypto.tink.proto.KeyStatusType.ENABLED
      case KeyStatusType.DISABLED =>
        return com.google.crypto.tink.proto.KeyStatusType.DISABLED
      case KeyStatusType.DESTROYED =>
        return com.google.crypto.tink.proto.KeyStatusType.DESTROYED
    }
    throw new IllegalArgumentException("Unknown key status type.")
  }
}
