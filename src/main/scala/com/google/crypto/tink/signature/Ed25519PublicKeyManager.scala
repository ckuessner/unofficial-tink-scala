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

import com.google.crypto.tink.PublicKeyVerify
import com.google.crypto.tink.internal.{KeyTypeManager, PrimitiveFactory}
import com.google.crypto.tink.proto.{Ed25519PublicKey, KeyData}
import com.google.crypto.tink.proto.KeyData.KeyMaterialType
import com.google.crypto.tink.subtle.Ed25519Verify

import java.security.GeneralSecurityException

/**
 * This key manager produces new instances of {@code Ed25519Verify}. It doesn't support key
 * generation.
 */
class Ed25519PublicKeyManager extends KeyTypeManager[Ed25519PublicKey](
  classOf[Ed25519PublicKey],
  new PrimitiveFactory[PublicKeyVerify, Ed25519PublicKey](classOf[PublicKeyVerify]) {
    override def getPrimitive(keyProto: Ed25519PublicKey) = new Ed25519Verify(keyProto.getKeyValue.toByteArray)
  }) {
  override def getKeyType = "type.googleapis.com/google.crypto.tink.Ed25519PublicKey"

  override def keyMaterialType: KeyData.KeyMaterialType = KeyMaterialType.ASYMMETRIC_PUBLIC

  @throws[GeneralSecurityException]
  override def validateKey(keyProto: Ed25519PublicKey): Unit = {
    if (keyProto.getKeyValue == null || keyProto.getKeyValue.size != Ed25519Verify.PUBLIC_KEY_LEN) {
      throw new GeneralSecurityException("invalid Ed25519 public key: incorrect key length")
    }
  }
}