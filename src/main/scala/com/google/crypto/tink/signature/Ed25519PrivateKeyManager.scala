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
package com.google.crypto.tink.signature

import com.google.crypto.tink.internal.KeyTypeManager.KeyFactory
import com.google.crypto.tink.internal.{KeyTypeManager, PrimitiveFactory, PrivateKeyTypeManager}
import com.google.crypto.tink.proto.KeyData.KeyMaterialType
import com.google.crypto.tink.proto.Keyset.Key
import com.google.crypto.tink.proto.{Ed25519PrivateKey, Ed25519PublicKey, KeyData}
import com.google.crypto.tink.subtle.Ed25519Sign
import com.google.crypto.tink.{KeyTemplate, PublicKeySign, Registry}
import com.google.protobuf.ByteString

import java.io.{IOException, InputStream}
import java.security.GeneralSecurityException
import java.util
import java.util.Collections

/**
 * This instance of {@code KeyManager} generates new {@code Ed25519PrivateKey} keys and produces new
 * instances of {@code Ed25519Sign}.
 */
object Ed25519PrivateKeyManager {
  /**
   * Registers the {@link Ed25519PrivateKeyManager} and the {@link Ed25519PublicKeyManager} with the
   * registry, so that the the Ed25519-Keys can be used with Tink.
   */
  @throws[GeneralSecurityException]
  def registerPair(newKeyAllowed: Boolean): Unit = {
    Registry.registerAsymmetricKeyManagers(new Ed25519PrivateKeyManager, new Ed25519PublicKeyManager, newKeyAllowed)
  }

  /**
   * @return A {@link KeyTemplate} that generates new instances of ED25519 keys.
   */
  def ed25519Template: KeyTemplate = KeyTemplate.create(new Ed25519PrivateKeyManager().getKeyType, KeyTemplate.OutputPrefixType.TINK)

  /**
   * @return A {@link KeyTemplate} that generates new instances of Ed25519 keys. Keys generated from
   *         this template creates raw signatures of exactly 64 bytes. It's compatible with most other
   *         libraries.
   */
  def rawEd25519Template: KeyTemplate = KeyTemplate.create(new Ed25519PrivateKeyManager().getKeyType, KeyTemplate.OutputPrefixType.RAW)
}

final class Ed25519PrivateKeyManager private[signature]
  extends PrivateKeyTypeManager[Ed25519PrivateKey, Ed25519PublicKey](
    classOf[Ed25519PrivateKey],
    classOf[Ed25519PublicKey],
    new PrimitiveFactory[PublicKeySign, Ed25519PrivateKey](classOf[PublicKeySign]) {
      @throws[GeneralSecurityException]
      override def getPrimitive(keyProto: Ed25519PrivateKey) = new Ed25519Sign(keyProto.getKeyValue.toByteArray)
    }) {

  override def getKeyType = "type.googleapis.com/google.crypto.tink.Ed25519PrivateKey"

  @throws[GeneralSecurityException]
  override def getPublicKey(key: Ed25519PrivateKey): Ed25519PublicKey = key.getPublicKey

  override def keyMaterialType: KeyData.KeyMaterialType = KeyMaterialType.ASYMMETRIC_PRIVATE

  @throws[GeneralSecurityException]
  override def validateKey(keyProto: Ed25519PrivateKey): Unit = {
    new Ed25519PublicKeyManager().validateKey(keyProto.getPublicKey)
    if (keyProto.getKeyValue.size != Ed25519Sign.SECRET_KEY_LEN) throw new GeneralSecurityException("invalid Ed25519 private key: incorrect key length")
  }

  override def keyFactory: KeyTypeManager.KeyFactory[Ed25519PrivateKey] = new KeyTypeManager.KeyFactory[Ed25519PrivateKey]() {
    @throws[GeneralSecurityException]
    override def createKey: Ed25519PrivateKey = {
      val keyPair = Ed25519Sign.KeyPair.newKeyPair
      val publicKey = Ed25519PublicKey.newBuilder.setKeyValue(ByteString.copyFrom(keyPair.getPublicKey)).build
      Ed25519PrivateKey.newBuilder.setKeyValue(ByteString.copyFrom(keyPair.getPrivateKey)).setPublicKey(publicKey).build
    }

    @throws[GeneralSecurityException]
    override def deriveKey(inputStream: InputStream): Ed25519PrivateKey = {
      val pseudorandomness = new Array[Byte](Ed25519Sign.SECRET_KEY_LEN)
      try {
        KeyFactory.readFully(inputStream, pseudorandomness)
        val keyPair = Ed25519Sign.KeyPair.newKeyPairFromSeed(pseudorandomness)
        val publicKey = Ed25519PublicKey.newBuilder.setKeyValue(ByteString.copyFrom(keyPair.getPublicKey)).build
        Ed25519PrivateKey.newBuilder.setKeyValue(ByteString.copyFrom(keyPair.getPrivateKey)).setPublicKey(publicKey).build
      } catch {
        case e: IOException =>
          throw new GeneralSecurityException("Reading pseudorandomness failed", e)
      }
    }

    override def keyFormats: Map[String, KeyTypeManager.KeyFactory.KeyFormat[Ed25519PrivateKey]] = {
      Map(
        "ED25519" -> new KeyTypeManager.KeyFactory.KeyFormat[Ed25519PrivateKey](KeyTemplate.OutputPrefixType.TINK),
        "ED25519_RAW" -> new KeyTypeManager.KeyFactory.KeyFormat[Ed25519PrivateKey](KeyTemplate.OutputPrefixType.RAW)
      )
    }
  }
}