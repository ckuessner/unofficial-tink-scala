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
package com.google.crypto.tink

import com.google.crypto.tink.proto.Keyset
import com.google.crypto.tink.proto.Keyset.Key
import com.google.crypto.tink.proto.OutputPrefixType.{CRUNCHY, LEGACY, RAW, TINK}

import java.nio.ByteBuffer
import java.security.GeneralSecurityException

/**
 * Constants and convenience methods that deal with crypto format.
 *
 * @since 1.0.0
 */
object CryptoFormat {
  /** Prefix size of Tink, Legacy and Crunchy output prefix types. */
  val NON_RAW_PREFIX_SIZE = 5
  /** Legacy or Crunchy prefix starts with \x00 and followed by a 4-byte key id. */
  val LEGACY_PREFIX_SIZE: Int = NON_RAW_PREFIX_SIZE
  val LEGACY_START_BYTE: Byte = 0.toByte
  /** Tink prefix starts with \x01 and followed by a 4-byte key id. */
  val TINK_PREFIX_SIZE: Int = NON_RAW_PREFIX_SIZE
  val TINK_START_BYTE: Byte = 1.toByte
  /** Raw prefix is empty. */
  val RAW_PREFIX_SIZE = 0
  val RAW_PREFIX = new Array[Byte](0)

  /**
   * Generates the prefix of all cryptographic outputs (ciphertexts, signatures, MACs, ...) produced
   * by the specified {@code key}. The prefix can be either empty (for RAW-type prefix), or consists
   * of a 1-byte indicator of the type of the prefix, followed by 4 bytes of {@code key.key_id} in
   * Big Endian encoding.
   *
   * @throws GeneralSecurityException if the prefix type of {@code key} is unknown.
   * @return a prefix.
   */
  @throws[GeneralSecurityException]
  def getOutputPrefix(key: Keyset.Key): Array[Byte] = key.getOutputPrefixType match {
    case LEGACY | CRUNCHY =>
      ByteBuffer.allocate(LEGACY_PREFIX_SIZE) // BIG_ENDIAN by default
        .put(LEGACY_START_BYTE)
        .putInt(key.getKeyId)
        .array
    case TINK =>
      ByteBuffer.allocate(TINK_PREFIX_SIZE) // BIG_ENDIAN by default
        .put(TINK_START_BYTE)
        .putInt(key.getKeyId)
        .array
    case RAW =>
      RAW_PREFIX
    case _ =>
      throw new GeneralSecurityException("unknown output prefix type")
  }
}