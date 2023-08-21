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

import com.google.common.truth.Truth.assertThat
import com.google.crypto.tink.{PublicKeySign, PublicKeyVerify}
import com.google.crypto.tink.internal.KeyTypeManager
import com.google.crypto.tink.proto.{Ed25519PrivateKey, Ed25519PublicKey}
import com.google.crypto.tink.proto.KeyData.KeyMaterialType
import com.google.crypto.tink.subtle.Random
import com.google.protobuf.ByteString
import org.junit.Assert.assertThrows
import org.junit.Test
import org.junit.runner.RunWith
import org.junit.runners.JUnit4

import java.security.GeneralSecurityException

/** Unit tests for Ed25519PublicKeyManager. */
@RunWith(classOf[JUnit4]) class Ed25519PublicKeyManagerTest {
  final private val signManager = new Ed25519PrivateKeyManager
  final private val factory = signManager.keyFactory
  final private val verifyManager = new Ed25519PublicKeyManager

  @Test
  @throws[Exception]
  def basics(): Unit = {
    assertThat(verifyManager.getKeyType).isEqualTo("type.googleapis.com/google.crypto.tink.Ed25519PublicKey")
    assertThat(verifyManager.keyMaterialType).isEqualTo(KeyMaterialType.ASYMMETRIC_PUBLIC)
  }

  @Test
  @throws[Exception]
  def validateKey_empty_throws(): Unit = {
    assertThrows(classOf[GeneralSecurityException], () => verifyManager.validateKey(Ed25519PublicKey.getDefaultInstance))
  }

  @throws[GeneralSecurityException]
  private def createPrivateKey = factory.createKey

  @Test
  @throws[Exception]
  def validateKey(): Unit = {
    val publicKey = signManager.getPublicKey(createPrivateKey)
    verifyManager.validateKey(publicKey)
  }

  //@Test
  //public void validateKey_wrongVersion() throws Exception {
  //  Ed25519PublicKey publicKey = signManager.getPublicKey(createPrivateKey());
  //  Ed25519PublicKey invalidKey = Ed25519PublicKey.newBuilder(publicKey).setVersion(1).build();
  //  assertThrows(GeneralSecurityException.class, () -> verifyManager.validateKey(invalidKey));
  //}
  @Test
  @throws[Exception]
  def validateKey_wrongLength31_throws(): Unit = {
    val publicKey = signManager.getPublicKey(createPrivateKey)
    val invalidKey = Ed25519PublicKey.newBuilder.setKeyValue(ByteString.copyFrom(Random.randBytes(31))).build
    assertThrows(classOf[GeneralSecurityException], () => verifyManager.validateKey(invalidKey))
  }

  @Test
  @throws[Exception]
  def validateKey_wrongLength64_throws(): Unit = {
    val publicKey = signManager.getPublicKey(createPrivateKey)
    val invalidKey = Ed25519PublicKey.newBuilder.setKeyValue(ByteString.copyFrom(Random.randBytes(64))).build
    assertThrows(classOf[GeneralSecurityException], () => verifyManager.validateKey(invalidKey))
  }

  @Test
  @throws[Exception]
  def createPrimitive(): Unit = {
    val privateKey = createPrivateKey
    val publicKey = signManager.getPublicKey(privateKey)
    val signer = signManager.getPrimitive(privateKey, classOf[PublicKeySign])
    val verifier = verifyManager.getPrimitive(publicKey, classOf[PublicKeyVerify])
    val message = Random.randBytes(135)
    verifier.verify(signer.sign(message), message)
  }

  @Test
  @throws[Exception]
  def createPrimitive_anotherKey_throws(): Unit = {
    val privateKey = createPrivateKey
    // Create a different key.
    val publicKey = signManager.getPublicKey(createPrivateKey)
    val signer = signManager.getPrimitive(privateKey, classOf[PublicKeySign])
    val verifier = verifyManager.getPrimitive(publicKey, classOf[PublicKeyVerify])
    val message = Random.randBytes(135)
    val signature = signer.sign(message)
    assertThrows(classOf[GeneralSecurityException], () => verifier.verify(signature, message))
  }
}