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
import com.google.crypto.tink.proto.{KeyData, XChaCha20Poly1305Key}
import com.google.crypto.tink.subtle.{Random, XChaCha20Poly1305}
import com.google.crypto.tink.{Aead, KeyTemplate, Registry}
import com.google.protobuf.ByteString

import java.io.{IOException, InputStream}
import java.security.GeneralSecurityException
import java.util
import java.util.Collections

/**
 * This instance of {@code KeyManager} generates new {@code XChaCha20Poly1305} keys and produces new
 * instances of {@code XChaCha20Poly1305}.
 */
object XChaCha20Poly1305KeyManager {
  private val KEY_SIZE_IN_BYTES = 32

  @throws[GeneralSecurityException]
  def register(newKeyAllowed: Boolean): Unit = {
    Registry.registerKeyManager(new XChaCha20Poly1305KeyManager, newKeyAllowed)
  }

  /**
   * @return a {@link KeyTemplate} that generates new instances of XChaCha20Poly1305 keys.
   */
  def xChaCha20Poly1305Template: KeyTemplate = KeyTemplate.create(
    new XChaCha20Poly1305KeyManager().getKeyType,
    KeyTemplate.OutputPrefixType.TINK
  )

  /**
   * @return a {@link KeyTemplate} that generates new instances of XChaCha20Poly1305 keys. Keys
   *         generated from this template create ciphertexts compatible with libsodium and other
   *         libraries.
   */
  def rawXChaCha20Poly1305Template: KeyTemplate = KeyTemplate.create(
    new XChaCha20Poly1305KeyManager().getKeyType,
    KeyTemplate.OutputPrefixType.RAW
  )
}

class XChaCha20Poly1305KeyManager private[tink]
  extends KeyTypeManager[XChaCha20Poly1305Key](
    classOf[XChaCha20Poly1305Key],
    new PrimitiveFactory[Aead, XChaCha20Poly1305Key](classOf[Aead]) {
      @throws[GeneralSecurityException]
      override def getPrimitive(key: XChaCha20Poly1305Key) = new XChaCha20Poly1305(key.getKeyValue.toByteArray)
    }) {

  override def getKeyType = "type.googleapis.com/google.crypto.tink.XChaCha20Poly1305Key"

  override def keyMaterialType: KeyData.KeyMaterialType = KeyMaterialType.SYMMETRIC

  @throws[GeneralSecurityException]
  override def validateKey(key: XChaCha20Poly1305Key): Unit = {
    if (key.getKeyValue.size != XChaCha20Poly1305KeyManager.KEY_SIZE_IN_BYTES) throw new GeneralSecurityException("invalid XChaCha20Poly1305Key: incorrect key length")
  }

  override def keyFactory: KeyTypeManager.KeyFactory[XChaCha20Poly1305Key] = new KeyTypeManager.KeyFactory[XChaCha20Poly1305Key]() {
    @throws[GeneralSecurityException]
    override def createKey: XChaCha20Poly1305Key =
      XChaCha20Poly1305Key
        .newBuilder
        .setKeyValue(ByteString.copyFrom(Random.randBytes(XChaCha20Poly1305KeyManager.KEY_SIZE_IN_BYTES)))
        .build

    @throws[GeneralSecurityException]
    override def deriveKey(inputStream: InputStream): XChaCha20Poly1305Key = {
      val pseudorandomness = new Array[Byte](XChaCha20Poly1305KeyManager.KEY_SIZE_IN_BYTES)
      try {
        KeyFactory.readFully(inputStream, pseudorandomness)
        XChaCha20Poly1305Key.newBuilder.setKeyValue(ByteString.copyFrom(pseudorandomness)).build
      } catch {
        case e: IOException =>
          throw new GeneralSecurityException("Reading pseudorandomness failed", e)
      }
    }

    @throws[GeneralSecurityException]
    override def keyFormats: Map[String, KeyFactory.KeyFormat[XChaCha20Poly1305Key]] = {
      Map(
        "XCHACHA20_POLY1305" -> new KeyFactory.KeyFormat[XChaCha20Poly1305Key](KeyTemplate.OutputPrefixType.TINK),
        "XCHACHA20_POLY1305_RAW" -> new KeyFactory.KeyFormat[XChaCha20Poly1305Key](KeyTemplate.OutputPrefixType.RAW)
      )
    }
  }
}