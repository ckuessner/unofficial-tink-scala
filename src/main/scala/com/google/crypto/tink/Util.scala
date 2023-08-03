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
// //////////////////////////////////////////////////////////////////////////////
package com.google.crypto.tink

import com.google.crypto.tink.proto.*

import java.io.{ByteArrayOutputStream, IOException, InputStream}
import java.nio.charset.Charset
import java.security.GeneralSecurityException

/** Various helpers. */
object Util {
  val UTF_8: Charset = Charset.forName("UTF-8")

  /** @return a KeysetInfo-proto from a {@code keyset} protobuf. */
  def getKeysetInfo(keyset: Keyset): KeysetInfo = {
    val info = KeysetInfo.newBuilder.setPrimaryKeyId(keyset.getPrimaryKeyId)
    for (key <- keyset.keys) {
      info.addKeyInfo(getKeyInfo(key))
    }
    info.build()
  }

  /** @return a KeyInfo-proto from a {@code key} protobuf. */
  def getKeyInfo(key: Keyset.Key): KeysetInfo.KeyInfo =
    KeysetInfo.KeyInfo.newBuilder
      .setTypeUrl(key.getKeyData.getTypeUrl)
      .setStatus(key.getStatus)
      .setOutputPrefixType(key.getOutputPrefixType)
      .setKeyId(key.getKeyId)
      .build()

  /**
   * Validates a {@code key}.
   *
   * @throws GeneralSecurityException if {@code key} is invalid.
   */
  @throws[GeneralSecurityException]
  def validateKey(key: Keyset.Key): Unit = {
    if (!key.hasKeyData) throw new GeneralSecurityException(String.format("key %d has no key data", key.getKeyId))
    if (key.getOutputPrefixType eq OutputPrefixType.UNKNOWN_PREFIX) throw new GeneralSecurityException(String.format("key %d has unknown prefix", key.getKeyId))
    if (key.getStatus eq KeyStatusType.UNKNOWN_STATUS) throw new GeneralSecurityException(String.format("key %d has unknown status", key.getKeyId))
  }

  /**
   * Validates a {@code Keyset}.
   *
   * @throws GeneralSecurityException if {@code keyset} is invalid.
   */
  @throws[GeneralSecurityException]
  def validateKeyset(keyset: Keyset): Unit = {
    val primaryKeyId = keyset.getPrimaryKeyId
    var hasPrimaryKey = false
    var containsOnlyPublicKeyMaterial = true
    var numEnabledKeys = 0
    for (key <- keyset.keys) {
      if (!(key.getStatus ne KeyStatusType.ENABLED)) {
        validateKey(key)
        if (key.getKeyId == primaryKeyId) {
          if (hasPrimaryKey) throw new GeneralSecurityException("keyset contains multiple primary keys")
          hasPrimaryKey = true
        }
        if (key.getKeyData.getKeyMaterialType ne KeyData.KeyMaterialType.ASYMMETRIC_PUBLIC) containsOnlyPublicKeyMaterial = false
        numEnabledKeys += 1
      }
    }
    if (numEnabledKeys == 0) throw new GeneralSecurityException("keyset must contain at least one ENABLED key")
    // Checks that a keyset contains a primary key, except when it contains only public keys.
    if (!hasPrimaryKey && !containsOnlyPublicKeyMaterial) throw new GeneralSecurityException("keyset doesn't contain a valid primary key")
  }

  /**
   * Reads all bytes from {@code inputStream}.
   */
  @throws[IOException]
  def readAll(inputStream: InputStream): Array[Byte] = {
    val result = new ByteArrayOutputStream
    val buf = new Array[Byte](1024)
    var count = 0
    while ({count = inputStream.read(buf); count != -1}) {
      result.write(buf, 0, count)
    }
    result.toByteArray
  }
}