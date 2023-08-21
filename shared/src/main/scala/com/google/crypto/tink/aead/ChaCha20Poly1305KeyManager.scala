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
package com.google.crypto.tink.aead

import com.google.crypto.tink.internal.KeyTypeManager.KeyFactory
import com.google.crypto.tink.internal.{KeyTypeManager, PrimitiveFactory}
import com.google.crypto.tink.proto.KeyData.KeyMaterialType
import com.google.crypto.tink.proto.{ChaCha20Poly1305Key, KeyData}
import com.google.crypto.tink.subtle.{ChaCha20Poly1305, Random}
import com.google.crypto.tink.{Aead, KeyTemplate, Registry, proto}
import com.google.protobuf.ByteString

import java.security.GeneralSecurityException
import java.util
import java.util.Collections

/**
 * This instance of {@code KeyManager} generates new {@code ChaCha20Poly1305} keys and produces new
 * instances of {@code ChaCha20Poly1305}.
 */
object ChaCha20Poly1305KeyManager {
  private val KEY_SIZE_IN_BYTES = 32

  @throws[GeneralSecurityException]
  def register(newKeyAllowed: Boolean): Unit = {
    Registry.registerKeyManager(new ChaCha20Poly1305KeyManager, newKeyAllowed)
  }

  /**
   * @return a {@link KeyTemplate} that generates new instances of ChaCha20Poly1305 keys.
   */
  def chaCha20Poly1305Template: KeyTemplate = KeyTemplate.create(new ChaCha20Poly1305KeyManager().getKeyType, KeyTemplate.OutputPrefixType.TINK)

  /**
   * @return a {@link KeyTemplate} that generates new instances of ChaCha20Poly1305 keys. Keys
   *         generated from this template create ciphertexts compatible with libsodium and other
   *         libraries.
   */
  def rawChaCha20Poly1305Template: KeyTemplate = KeyTemplate.create(new ChaCha20Poly1305KeyManager().getKeyType, KeyTemplate.OutputPrefixType.RAW)
}

class ChaCha20Poly1305KeyManager private[tink] extends KeyTypeManager[ChaCha20Poly1305Key](classOf[ChaCha20Poly1305Key], new PrimitiveFactory[Aead, ChaCha20Poly1305Key](classOf[Aead]) {
  @throws[GeneralSecurityException]
  override def getPrimitive(key: ChaCha20Poly1305Key) = new ChaCha20Poly1305(key.getKeyValue.toByteArray)
}) {
  override def getKeyType = "type.googleapis.com/google.crypto.tink.ChaCha20Poly1305Key"

  override def keyMaterialType: KeyData.KeyMaterialType = KeyMaterialType.SYMMETRIC

  @throws[GeneralSecurityException]
  override def validateKey(key: ChaCha20Poly1305Key): Unit = {
    if (key.getKeyValue.size != ChaCha20Poly1305KeyManager.KEY_SIZE_IN_BYTES) throw new GeneralSecurityException("invalid ChaCha20Poly1305Key: incorrect key length")
  }

  override def keyFactory: KeyTypeManager.KeyFactory[ChaCha20Poly1305Key] = new KeyTypeManager.KeyFactory[ChaCha20Poly1305Key]() {
    @throws[GeneralSecurityException]
    override def createKey: ChaCha20Poly1305Key = {
      ChaCha20Poly1305Key
        .newBuilder
        .setKeyValue(ByteString.copyFrom(Random.randBytes(ChaCha20Poly1305KeyManager.KEY_SIZE_IN_BYTES)))
        .build()
    }

    @throws[GeneralSecurityException]
    override def keyFormats: Map[String, KeyFactory.KeyFormat[ChaCha20Poly1305Key]] = {
      Map(
        "CHACHA20_POLY1305" -> new KeyFactory.KeyFormat[ChaCha20Poly1305Key](KeyTemplate.OutputPrefixType.TINK),
        "CHACHA20_POLY1305_RAW" -> new KeyFactory.KeyFormat[ChaCha20Poly1305Key](KeyTemplate.OutputPrefixType.RAW)
      )
    }
  }
}